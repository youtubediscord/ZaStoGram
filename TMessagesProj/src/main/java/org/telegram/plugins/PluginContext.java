package org.telegram.plugins;

import android.content.Context;
import android.content.SharedPreferences;

import com.chaquo.python.PyObject;

import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;

import java.lang.reflect.Constructor;
import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * Per-plugin host context. One instance is created per loaded plugin and handed to the
 * Python BasePlugin instance as `self._context`. It owns that plugin's installed hooks
 * (so they can be removed on disable/unload) and its persisted settings.
 *
 * All methods are called from Python via Chaquopy and must be defensive.
 */
public class PluginContext {

    public final String pluginId;
    private final List<XC_MethodHook.Unhook> unhooks = new ArrayList<>();

    public PluginContext(String pluginId) {
        this.pluginId = pluginId;
    }

    // ---------------------------------------------------------------- hooking

    /** Hook a single method/constructor. Returns the Unhook handle (also tracked for cleanup). */
    public XC_MethodHook.Unhook hookMethod(Member method, PyObject pyHook) {
        if (method == null || pyHook == null) {
            return null;
        }
        try {
            XC_MethodHook.Unhook u = XposedBridge.hookMethod(method, new PythonHook(pluginId, pyHook));
            synchronized (unhooks) {
                unhooks.add(u);
            }
            return u;
        } catch (Throwable t) {
            PluginsController.logError(pluginId, "hook_method(" + method + ")", t);
            return null;
        }
    }

    /** Hook every declared constructor of a class. Returns the list of Unhook handles. */
    public List<XC_MethodHook.Unhook> hookAllConstructors(Class<?> clazz, PyObject pyHook) {
        List<XC_MethodHook.Unhook> result = new ArrayList<>();
        if (clazz == null || pyHook == null) {
            return result;
        }
        for (Constructor<?> c : clazz.getDeclaredConstructors()) {
            try {
                XC_MethodHook.Unhook u = XposedBridge.hookMethod(c, new PythonHook(pluginId, pyHook));
                synchronized (unhooks) {
                    unhooks.add(u);
                }
                result.add(u);
            } catch (Throwable t) {
                PluginsController.logError(pluginId, "hook_all_constructors(" + clazz + ")", t);
            }
        }
        return result;
    }

    /** Remove a single hook previously returned by hookMethod(). */
    public void unhook(Object handle) {
        if (!(handle instanceof XC_MethodHook.Unhook)) {
            return;
        }
        XC_MethodHook.Unhook u = (XC_MethodHook.Unhook) handle;
        try {
            u.unhook();
        } catch (Throwable t) {
            FileLog.e(t);
        }
        synchronized (unhooks) {
            unhooks.remove(u);
        }
    }

    /** Remove all hooks installed by this plugin (called on disable/unload). */
    public void unhookAll() {
        synchronized (unhooks) {
            for (XC_MethodHook.Unhook u : unhooks) {
                try {
                    u.unhook();
                } catch (Throwable t) {
                    FileLog.e(t);
                }
            }
            unhooks.clear();
        }
    }

    // ---------------------------------------------------------------- settings

    private SharedPreferences prefs() {
        Context ctx = ApplicationLoader.applicationContext;
        return ctx.getSharedPreferences("plugin_settings_" + pluginId, Context.MODE_PRIVATE);
    }

    public Object getSetting(String key, Object def) {
        try {
            SharedPreferences p = prefs();
            if (!p.contains(key)) {
                return def;
            }
            if (def instanceof Boolean) {
                return p.getBoolean(key, (Boolean) def);
            }
            if (def instanceof Integer) {
                return p.getInt(key, (Integer) def);
            }
            if (def instanceof Long) {
                return p.getLong(key, (Long) def);
            }
            if (def instanceof Float) {
                return p.getFloat(key, (Float) def);
            }
            if (def instanceof Double) {
                return Double.longBitsToDouble(p.getLong(key, Double.doubleToRawLongBits((Double) def)));
            }
            return p.getString(key, def == null ? null : def.toString());
        } catch (Throwable t) {
            return def;
        }
    }

    public void setSetting(String key, Object value) {
        try {
            SharedPreferences.Editor e = prefs().edit();
            if (value instanceof Boolean) {
                e.putBoolean(key, (Boolean) value);
            } else if (value instanceof Integer) {
                e.putInt(key, (Integer) value);
            } else if (value instanceof Long) {
                e.putLong(key, (Long) value);
            } else if (value instanceof Float) {
                e.putFloat(key, (Float) value);
            } else if (value instanceof Double) {
                // Chaquopy maps a Python float to java.lang.Double; SharedPreferences has no
                // putDouble, so store the exact bit pattern as a long.
                e.putLong(key, Double.doubleToRawLongBits((Double) value));
            } else {
                e.putString(key, value == null ? null : value.toString());
            }
            e.apply();
        } catch (Throwable t) {
            FileLog.e(t);
        }
    }

    // ---------------------------------------------------------------- logging

    public void log(String msg) {
        PluginsController.log(pluginId, msg);
    }

    // ---------------------------------------------------------------- callback

    /**
     * Bridges a Pine/Xposed hook callback to the plugin's Python MethodHook instance.
     * Exceptions thrown by plugin code are swallowed so a bad hook can't crash the host.
     */
    private static final class PythonHook extends XC_MethodHook {
        private final String pluginId;
        private final PyObject pyHook;

        PythonHook(String pluginId, PyObject pyHook) {
            this.pluginId = pluginId;
            this.pyHook = pyHook;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            try {
                pyHook.callAttr("before_hooked_method", param);
            } catch (Throwable t) {
                PluginsController.logError(pluginId, "before_hooked_method", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            try {
                pyHook.callAttr("after_hooked_method", param);
            } catch (Throwable t) {
                PluginsController.logError(pluginId, "after_hooked_method", t);
            }
        }
    }
}
