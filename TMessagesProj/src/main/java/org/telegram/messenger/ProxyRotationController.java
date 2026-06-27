package org.telegram.messenger;

import android.content.SharedPreferences;
import org.telegram.tgnet.ConnectionsManager;

import java.util.Arrays;
import java.util.List;

public class ProxyRotationController implements NotificationCenter.NotificationCenterDelegate {
    private final static ProxyRotationController INSTANCE = new ProxyRotationController();

    public final static int DEFAULT_TIMEOUT_INDEX = 1;
    private final static long TERMINAL_STAGE_SWITCH_DELAY_MS = 900L;
    public final static List<Integer> ROTATION_TIMEOUTS = Arrays.asList(
            5, 10, 15, 30, 60
    );
    private static final Object ROTATION_SETTINGS_CHANGE = new Object();

    private final ProxyRotationEngine engine = new ProxyRotationEngine();
    private Runnable scheduledSwitchRunnable;

    public static void init() {
        INSTANCE.initInternal();
    }

    private void switchToProxy(SharedConfig.ProxyInfo info, String reason) {
        engine.recordSwitch(info);
        SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
        editor.putString("proxy_ip", info.address);
        editor.putString("proxy_pass", info.password);
        editor.putString("proxy_user", info.username);
        editor.putInt("proxy_port", info.port);
        editor.putString("proxy_secret", info.secret);
        editor.putBoolean("proxy_enabled", true);

        if (!info.secret.isEmpty()) {
            editor.putBoolean("proxy_enabled_calls", false);
        }
        editor.apply();

        SharedConfig.currentProxy = info;
        ProxyRuntimeStateStore.markConnectionStarting(info);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyChangedByRotation);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged, ROTATION_SETTINGS_CHANGE);
        ConnectionsManager.setProxySettings(true, SharedConfig.currentProxy.address, SharedConfig.currentProxy.port, SharedConfig.currentProxy.username, SharedConfig.currentProxy.password, SharedConfig.currentProxy.secret);
        if ("fallback".equals(reason)) {
            log("switch fallback endpoint=" + endpoint(info) + " ping=" + info.ping);
        } else {
            log("switch fresh endpoint=" + endpoint(info) + " ping=" + info.ping);
        }
    }

    private void initInternal() {
        for (int i = 0; i < UserConfig.MAX_ACCOUNT_COUNT; i++) {
            NotificationCenter.getInstance(i).addObserver(this, NotificationCenter.didUpdateConnectionState);
            NotificationCenter.getInstance(i).addObserver(this, NotificationCenter.proxyConnectionStageChanged);
        }
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxySettingsChanged);
    }

    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.proxySettingsChanged) {
            cancelScheduledSwitchRunnable();
            if (isRotationOwnedSettingsChange(args)) {
                engine.onRotationSettingsApplied();
                log("cancel rotation_settings_applied");
                return;
            }
            ProxyRuntimeStateStore.clearRotatedAwayTelemetry();
            engine.onSettingsChanged();
            log("cancel settings_changed");
        } else if (id == NotificationCenter.didUpdateConnectionState && account == UserConfig.selectedAccount) {
            if (!SharedConfig.isProxyEnabled() || !SharedConfig.proxyRotationEnabled || SharedConfig.proxyList.size() <= 1) {
                return;
            }

            int state = ConnectionsManager.getInstance(account).getConnectionState();

            if (state == ConnectionsManager.ConnectionStateConnectingToProxy) {
                if (!engine.hasScheduledAttempt()) {
                    long timeoutMs = rotationTimeoutMillis();
                    log("schedule_after_connecting timeout_s=" + (timeoutMs / 1000L));
                    scheduleSwitch(timeoutMs, ProxyCheckDiagnostics.CONNECTING_TIMEOUT);
                }
            } else {
                if ((state == ConnectionsManager.ConnectionStateConnected || state == ConnectionsManager.ConnectionStateUpdating) && SharedConfig.currentProxy != null) {
                    if (ProxyRuntimeStateStore.isEndpointRotatedAway(SharedConfig.currentProxy)) {
                        log("connected ignored_rotated_away endpoint=" + endpoint(SharedConfig.currentProxy));
                        return;
                    }
                    ProxyRuntimeStateStore.markConnected(SharedConfig.currentProxy);
                    engine.onConnected();
                }
                cancelScheduledSwitch("state=" + state);
                log("cancel state=" + state);
            }
        } else if (id == NotificationCenter.proxyConnectionStageChanged && account == UserConfig.selectedAccount) {
            if (!SharedConfig.isProxyEnabled() || !SharedConfig.proxyRotationEnabled || SharedConfig.proxyList.size() <= 1) {
                return;
            }
            if (args == null || args.length == 0 || !(args[0] instanceof String)) {
                return;
            }
            String diagnostic = (String) args[0];
            if (args.length < 2 || !(args[1] instanceof String)) {
                return;
            }
            String endpointKey = (String) args[1];
            if (ProxyPhasePolicy.isProxyUsableSuccessPhase(diagnostic)
                    && ProxyEndpointKey.matchesLiveStage(SharedConfig.currentProxy, endpointKey)
                    && ProxyRuntimeStateStore.isCurrentProxyUsable(SharedConfig.currentProxy)) {
                cancelScheduledSwitch("usable_success");
                log("cancel usable_success phase=" + ProxyCheckDiagnostics.normalize(diagnostic) + " endpoint=" + endpointKey + " hold_ms=" + ProxyRuntimeStateStore.usableSuccessRemainingMs(SharedConfig.currentProxy));
                return;
            }
            if (!ProxyRuntimeStateStore.shouldScheduleFallback(account, diagnostic, endpointKey)) {
                return;
            }
            int state = ConnectionsManager.getInstance(account).getConnectionState();
            if (state != ConnectionsManager.ConnectionStateConnectingToProxy) {
                return;
            }
            if (engine.hasScheduledAttempt()) {
                log("schedule_after_stage skipped already_scheduled phase=" + ProxyCheckDiagnostics.normalize(diagnostic));
                return;
            }
            log("schedule_after_stage phase=" + ProxyCheckDiagnostics.normalize(diagnostic) + " delay_ms=" + TERMINAL_STAGE_SWITCH_DELAY_MS);
            scheduleSwitch(TERMINAL_STAGE_SWITCH_DELAY_MS, "terminal_stage");
        }
    }

    private void scheduleSwitch(long delayMs, String reason) {
        cancelScheduledSwitchRunnable();
        ProxyRotationEngine.Attempt attempt = engine.beginScheduledAttempt(SharedConfig.currentProxy, delayMs, reason);
        final Runnable[] runnableHolder = new Runnable[1];
        runnableHolder[0] = () -> runScheduledSwitch(attempt, runnableHolder[0]);
        scheduledSwitchRunnable = runnableHolder[0];
        AndroidUtilities.runOnUIThread(scheduledSwitchRunnable, delayMs);
        log("scheduled_switch reason=" + reason + " delay_ms=" + delayMs + " generation=" + attempt.generation);
    }

    private void runScheduledSwitch(ProxyRotationEngine.Attempt attempt, Runnable runnable) {
        if (scheduledSwitchRunnable == runnable) {
            scheduledSwitchRunnable = null;
        }
        log("scheduled_check skipped background_disabled reason=" + attempt.reason);
        ProxyRotationEngine.SwitchDecision decision = engine.completeScheduledAttempt(attempt, SharedConfig.currentProxy);
        if (decision.stale) {
            log("scheduled_check stale reason=" + decision.decision);
            return;
        }
        if (decision.proxyInfo == null) {
            log(decision.decision + " wait_ms=" + decision.waitMs);
            return;
        }
        switchToProxy(decision.proxyInfo, decision.decision);
    }

    private void cancelScheduledSwitch(String reason) {
        cancelScheduledSwitchRunnable();
        engine.cancelScheduledAttempt(reason);
    }

    private void cancelScheduledSwitchRunnable() {
        if (scheduledSwitchRunnable != null) {
            AndroidUtilities.cancelRunOnUIThread(scheduledSwitchRunnable);
            scheduledSwitchRunnable = null;
        }
    }

    private boolean isRotationOwnedSettingsChange(Object... args) {
        return args != null && args.length > 0 && args[0] == ROTATION_SETTINGS_CHANGE;
    }

    private long rotationTimeoutMillis() {
        int timeoutIndex = SharedConfig.proxyRotationTimeout;
        if (timeoutIndex < 0 || timeoutIndex >= ROTATION_TIMEOUTS.size()) {
            timeoutIndex = DEFAULT_TIMEOUT_INDEX;
        }
        return ROTATION_TIMEOUTS.get(timeoutIndex) * 1000L;
    }

    private void log(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_rotation " + message);
        }
    }

    private String endpoint(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return "null";
        }
        return proxyInfo.address + ":" + proxyInfo.port;
    }
}
