"""
ZaStoGram plugin SDK — base classes (exteraGram-compatible).

A plugin is a single .plugin Python file that defines module-level metadata
(__id__, __name__, __version__, __min_version__, __icon__, ...) and a subclass of
BasePlugin. The host (PluginsController + _plugin_loader) instantiates it, injects a
Java PluginContext as ``self._context`` and drives its lifecycle.

Method hooking is backed by Pine's Xposed-compatible engine on the Java side; the
``param`` handed to hook callbacks is a real de.robv.android.xposed MethodHookParam
(``param.thisObject``, ``param.args``, ``param.getResult()``, ``param.setResult(...)``).
"""


class HookStrategy:
    """Return strategy for high-level request/response hooks."""
    DEFAULT = 0   # let the original result flow through unchanged
    MODIFY = 1    # deliver HookResult.response instead
    CANCEL = 2    # swallow the result entirely
    # exteraGram aliases
    REPLACE = 1


class HookResult:
    def __init__(self, strategy=HookStrategy.DEFAULT, response=None):
        self.strategy = strategy
        self.response = response


class MethodHook:
    """
    Xposed-style method hook. Subclass and override before/after_hooked_method.
    ``param`` is a Java MethodHookParam.
    """

    def before_hooked_method(self, param):
        pass

    def after_hooked_method(self, param):
        pass


class XposedHook(MethodHook):
    """Convenience hook built from plain callables: XposedHook(before=fn, after=fn)."""

    def __init__(self, before=None, after=None):
        self._before = before
        self._after = after

    def before_hooked_method(self, param):
        if self._before is not None:
            self._before(param)

    def after_hooked_method(self, param):
        if self._after is not None:
            self._after(param)


class BasePlugin:

    def __init__(self):
        # Injected by the loader before on_plugin_load():
        self._context = None      # Java org.telegram.plugins.PluginContext
        self.id = None
        self.name = None
        # Request-name filters registered via add_hook(); see post_request_hook dispatch.
        self._request_hooks = []

    # ------------------------------------------------------------------ lifecycle

    def on_plugin_load(self):
        """Called once when the plugin is enabled. Install hooks here."""
        pass

    def on_plugin_unload(self):
        """Called when the plugin is disabled/removed. Hooks are auto-removed by the host."""
        pass

    def create_settings(self):
        """Return a list of ui.settings items to render on the plugin's settings screen."""
        return []

    # ------------------------------------------------------------------ high-level hooks

    def pre_request_hook(self, request_name, account, request):
        """Called before an outgoing request is sent (override to inspect/cancel)."""
        return HookResult(strategy=HookStrategy.DEFAULT)

    def post_request_hook(self, request_name, account, response, error):
        """Called just before a response is delivered (override to inspect/modify/cancel)."""
        return HookResult(strategy=HookStrategy.DEFAULT)

    # ------------------------------------------------------------------ method hooking

    def hook_method(self, method, hook):
        """Hook a single java.lang.reflect.Member with a MethodHook. Returns an Unhook."""
        return self._context.hookMethod(method, hook)

    def hook_all_constructors(self, clazz, hook):
        """Hook every constructor of a java.lang.Class. Returns a list of Unhooks."""
        return self._context.hookAllConstructors(clazz, hook)

    def unhook_method(self, unhook):
        """Remove a previously installed hook."""
        if unhook is not None:
            self._context.unhook(unhook)

    def add_hook(self, request_name, match_substring=False):
        """
        Register interest in a request by (TL) name so post_request_hook fires for it.
        e.g. add_hook("TL_account_getAuthorizations") or add_hook("getAuthorizations", True).
        """
        self._request_hooks.append((str(request_name), bool(match_substring)))
        return (request_name, match_substring)

    def _matches_request(self, request_name):
        if not self._request_hooks:
            return None  # no filters registered → caller decides
        for name, substring in self._request_hooks:
            if substring:
                if name in str(request_name):
                    return True
            elif name == str(request_name):
                return True
        return False

    # ------------------------------------------------------------------ settings storage

    def get_setting(self, key, default=None):
        return self._context.getSetting(key, default)

    def set_setting(self, key, value):
        self._context.setSetting(key, value)

    # ------------------------------------------------------------------ logging

    def log(self, msg):
        try:
            self._context.log(str(msg))
        except Exception:
            pass
