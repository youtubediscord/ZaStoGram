"""
extera_utils — small compatibility helpers (class-proxy DSL, text/metadata utilities).

Kept intentionally light; extend as community plugins require more of the surface.
"""

from java import dynamic_proxy  # re-exported for convenience


def get_resource_id(name, kind="drawable"):
    """Resolve an app resource id by name (e.g. get_resource_id('msg_link'))."""
    from org.telegram.messenger import ApplicationLoader
    try:
        ctx = ApplicationLoader.applicationContext
        return ctx.getResources().getIdentifier(name, kind, ctx.getPackageName())
    except Exception:
        return 0
