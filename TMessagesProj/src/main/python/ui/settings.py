"""
ui.settings — declarative rows for a plugin's settings screen.

A plugin returns a list of these from create_settings(). The host renders them with
native Telegram cells; each item exposes to_model() producing a flat dict the Java UI
consumes (so Java never touches Python objects). User interaction is routed back to
on_change(value) / on_click(view) by the loader.
"""


class _Item:
    type = "item"
    key = None
    on_change = None
    on_click = None

    def to_model(self, plugin, index):
        return {"type": self.type, "index": index}


class Header(_Item):
    type = "header"

    def __init__(self, text=""):
        self.text = text

    def to_model(self, plugin, index):
        return {"type": "header", "index": index, "text": str(self.text)}


class Divider(_Item):
    """A section separator; optional text becomes a footer/info line."""
    type = "divider"

    def __init__(self, text=""):
        self.text = text

    def to_model(self, plugin, index):
        return {"type": "divider", "index": index, "text": str(self.text or "")}


class Switch(_Item):
    type = "switch"

    def __init__(self, key, text, default=False, subtext="", icon=None, on_change=None):
        self.key = key
        self.text = text
        self.default = default
        self.subtext = subtext
        self.icon = icon
        self.on_change = on_change

    def to_model(self, plugin, index):
        value = plugin.get_setting(self.key, self.default) if plugin is not None else self.default
        return {"type": "switch", "index": index, "key": self.key,
                "text": str(self.text), "subtext": str(self.subtext or ""),
                "icon": self.icon, "value": bool(value)}


class Input(_Item):
    type = "input"

    def __init__(self, key, text, default="", subtext="", icon=None, on_change=None):
        self.key = key
        self.text = text
        self.default = default
        self.subtext = subtext
        self.icon = icon
        self.on_change = on_change

    def to_model(self, plugin, index):
        value = plugin.get_setting(self.key, self.default) if plugin is not None else self.default
        return {"type": "input", "index": index, "key": self.key,
                "text": str(self.text), "subtext": str(self.subtext or ""),
                "icon": self.icon, "value": "" if value is None else str(value)}


class Text(_Item):
    """A clickable text row. on_click(view) is called with the row's View."""
    type = "text"

    def __init__(self, text="", icon=None, subtext="", on_click=None, accent=False, red=False):
        self.text = text
        self.icon = icon
        self.subtext = subtext
        self.on_click = on_click
        self.accent = accent
        self.red = red

    def to_model(self, plugin, index):
        return {"type": "text", "index": index, "text": str(self.text),
                "subtext": str(self.subtext or ""), "icon": self.icon,
                "accent": bool(self.accent), "red": bool(self.red)}


class Selector(_Item):
    """A single-choice row; persisted value is the selected option index (int)."""
    type = "selector"

    def __init__(self, key, text, options, default=0, subtext="", on_change=None):
        self.key = key
        self.text = text
        self.options = list(options)
        self.default = default
        self.subtext = subtext
        self.on_change = on_change

    def to_model(self, plugin, index):
        from java.util import ArrayList
        value = plugin.get_setting(self.key, self.default) if plugin is not None else self.default
        opts = ArrayList()
        for o in self.options:
            opts.add(str(o))
        try:
            ivalue = int(value)
        except Exception:
            ivalue = 0
        return {"type": "selector", "index": index, "key": self.key,
                "text": str(self.text), "subtext": str(self.subtext or ""),
                "options": opts, "value": ivalue}
