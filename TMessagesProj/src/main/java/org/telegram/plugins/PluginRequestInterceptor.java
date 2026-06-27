package org.telegram.plugins;

import org.telegram.messenger.FileLog;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.QuickAckDelegate;
import org.telegram.tgnet.RequestDelegate;
import org.telegram.tgnet.RequestDelegateTimestamp;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.WriteToSocketDelegate;

import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * Lets plugins observe and rewrite MTProto responses via BasePlugin.post_request_hook.
 *
 * Strategy: hook the 9-arg {@link ConnectionsManager#sendRequest} (every RequestDelegate-based
 * overload funnels into it) and, in beforeHookedMethod, wrap the onComplete delegate (args[1])
 * so plugins run just before the response is delivered. Gated by {@link #active} so there is no
 * per-request work unless a plugin actually registers a request hook.
 */
public final class PluginRequestInterceptor {

    public static final String CANCEL_SENTINEL = "__zasto_cancel__";

    private static volatile boolean active = false;
    private static volatile boolean installed = false;

    private PluginRequestInterceptor() {
    }

    /** Enable/disable dispatch; installs the underlying hook lazily on first activation. */
    public static synchronized void setActive(boolean value) {
        active = value;
        if (value && !installed) {
            install();
        }
    }

    private static void install() {
        if (installed) {
            return;
        }
        try {
            Method m = ConnectionsManager.class.getDeclaredMethod(
                    "sendRequest",
                    TLObject.class, RequestDelegate.class, RequestDelegateTimestamp.class,
                    QuickAckDelegate.class, WriteToSocketDelegate.class,
                    int.class, int.class, int.class, boolean.class);
            XposedBridge.hookMethod(m, new SendRequestHook());
            installed = true;
            FileLog.d("zasto plugins: request interceptor installed");
        } catch (Throwable t) {
            FileLog.e("zasto plugins: failed to install request interceptor", t);
        }
    }

    private static int accountOf(Object connectionsManager) {
        Object v = PluginUtils.getPrivateField(connectionsManager, "currentAccount");
        if (v instanceof Integer) {
            return (Integer) v;
        }
        return UserConfig.selectedAccount;
    }

    private static final class SendRequestHook extends XC_MethodHook {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (!active) {
                return;
            }
            try {
                final Object[] args = param.args;
                if (args == null || args.length < 2 || !(args[1] instanceof RequestDelegate)) {
                    return; // no onComplete delegate (e.g. timestamp/updates path)
                }
                final RequestDelegate orig = (RequestDelegate) args[1];
                final TLObject request = (args[0] instanceof TLObject) ? (TLObject) args[0] : null;
                final String name = request != null ? request.getClass().getSimpleName() : "";
                final int account = accountOf(param.thisObject);

                args[1] = (RequestDelegate) (response, error) -> {
                    TLObject deliver = response;
                    try {
                        Object out = PluginsController.getInstance()
                                .dispatchPostRequest(name, account, response, error);
                        if (out == null) {
                            return; // HookStrategy.CANCEL — swallow the response
                        }
                        if (out instanceof TLObject) {
                            deliver = (TLObject) out;
                        }
                    } catch (Throwable t) {
                        FileLog.e(t);
                    }
                    orig.run(deliver, error);
                };
            } catch (Throwable t) {
                FileLog.e(t);
            }
        }
    }
}
