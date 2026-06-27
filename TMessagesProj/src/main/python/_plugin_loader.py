"""
_plugin_loader — host-side orchestration called from PluginsController (Java).

Owns the live plugin instances and their settings item lists. Keeps the messy parts
(exec, subclass discovery, callback dispatch, strategy handling) in Python where they
are simplest, and exposes a small, Java-friendly surface.
"""

import traceback

_INSTANCES = {}   # plugin_id -> BasePlugin instance
_SETTINGS = {}    # plugin_id -> list of ui.settings items (last rendered)
_MODULES = {}     # plugin_id -> module globals dict (keeps the module alive)

CANCEL_SENTINEL = "__zasto_cancel__"


def _read_source(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def instantiate(path, plugin_id, context):
    """Exec the plugin file, instantiate its BasePlugin subclass and run on_plugin_load()."""
    from base_plugin import BasePlugin

    src = _read_source(path)
    g = {
        "__name__": "plugin_" + str(plugin_id),
        "__file__": str(path),
        "__builtins__": __builtins__,
    }
    code = compile(src, str(path), "exec")
    exec(code, g)

    plugin_cls = None
    for value in list(g.values()):
        if isinstance(value, type) and issubclass(value, BasePlugin) and value is not BasePlugin:
            plugin_cls = value
            break
    if plugin_cls is None:
        raise RuntimeError("no BasePlugin subclass found in " + str(path))

    inst = plugin_cls()
    inst._context = context
    inst.id = plugin_id
    inst.name = g.get("__name__") if isinstance(g.get("__name__"), str) else plugin_id

    _MODULES[plugin_id] = g
    _INSTANCES[plugin_id] = inst
    try:
        inst.on_plugin_load()
    except Exception:
        _INSTANCES.pop(plugin_id, None)
        _MODULES.pop(plugin_id, None)
        raise
    return inst


def unload(plugin_id):
    inst = _INSTANCES.pop(plugin_id, None)
    _SETTINGS.pop(plugin_id, None)
    _MODULES.pop(plugin_id, None)
    if inst is not None:
        try:
            inst.on_plugin_unload()
        except Exception:
            traceback.print_exc()


def is_loaded(plugin_id):
    return plugin_id in _INSTANCES


# ------------------------------------------------------------------ settings bridge

def get_settings_model(plugin_id):
    """Return a java.util.List<HashMap<String,Object>> describing the settings rows."""
    from java.util import ArrayList, HashMap

    out = ArrayList()
    inst = _INSTANCES.get(plugin_id)
    if inst is None:
        return out
    try:
        items = inst.create_settings() or []
    except Exception:
        traceback.print_exc()
        return out

    _SETTINGS[plugin_id] = list(items)
    for idx, item in enumerate(items):
        try:
            model = item.to_model(inst, idx)
        except Exception:
            traceback.print_exc()
            continue
        row = HashMap()
        for key, value in model.items():
            row.put(key, value)
        out.add(row)
    return out


def on_setting_change(plugin_id, key, value):
    inst = _INSTANCES.get(plugin_id)
    if inst is None:
        return
    try:
        inst.set_setting(key, value)
    except Exception:
        traceback.print_exc()
    for item in _SETTINGS.get(plugin_id, []):
        if getattr(item, "key", None) == key:
            callback = getattr(item, "on_change", None)
            if callback is not None:
                try:
                    callback(value)
                except Exception:
                    traceback.print_exc()
            break


def on_setting_click(plugin_id, index, view=None):
    items = _SETTINGS.get(plugin_id, [])
    if 0 <= index < len(items):
        callback = getattr(items[index], "on_click", None)
        if callback is not None:
            try:
                callback(view)
            except Exception:
                traceback.print_exc()


# ------------------------------------------------------------------ request hook bridge

def has_request_hooks():
    from base_plugin import BasePlugin
    for inst in _INSTANCES.values():
        if getattr(inst, "_request_hooks", None):
            return True
        if type(inst).post_request_hook is not BasePlugin.post_request_hook:
            return True
        if type(inst).pre_request_hook is not BasePlugin.pre_request_hook:
            return True
    return False


def dispatch_post_request(req_name, account, response, error):
    """
    Run every interested plugin's post_request_hook. Returns the (possibly replaced)
    response object to deliver, or CANCEL_SENTINEL to drop it.
    """
    from base_plugin import BasePlugin, HookStrategy

    current = response
    for inst in list(_INSTANCES.values()):
        try:
            matches = inst._matches_request(req_name)
        except Exception:
            matches = None
        if matches is False:
            continue
        if matches is None and type(inst).post_request_hook is BasePlugin.post_request_hook:
            continue
        try:
            result = inst.post_request_hook(req_name, account, current, error)
        except Exception:
            traceback.print_exc()
            continue
        if result is None:
            continue
        strategy = getattr(result, "strategy", HookStrategy.DEFAULT)
        if strategy == HookStrategy.CANCEL:
            return CANCEL_SENTINEL
        if strategy == HookStrategy.MODIFY:
            new_response = getattr(result, "response", None)
            if new_response is not None:
                current = new_response
    return current
