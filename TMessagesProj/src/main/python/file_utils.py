"""file_utils — app directories and small file I/O helpers for plugins."""

import os

from org.telegram.messenger import ApplicationLoader


def get_files_dir():
    return ApplicationLoader.applicationContext.getFilesDir().getAbsolutePath()


def get_cache_dir():
    return ApplicationLoader.applicationContext.getCacheDir().getAbsolutePath()


def plugin_data_dir(plugin_id):
    """A private, persistent directory a plugin can use for its own data."""
    path = os.path.join(get_files_dir(), "plugins_data", str(plugin_id))
    os.makedirs(path, exist_ok=True)
    return path


def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default


def write_text(path, text):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def exists(path):
    return os.path.exists(path)
