"""client_utils — fragments, accounts, queues and message sending for plugins."""

from java import dynamic_proxy
from java.lang import Runnable

from org.telegram.plugins import PluginUtils


def get_last_fragment():
    """The top-most visible BaseFragment, or None."""
    return PluginUtils.getLastFragment()


def get_context():
    """Best-effort Context: visible activity if any, else the application context."""
    return PluginUtils.getContext()


def get_current_account():
    return PluginUtils.getCurrentAccount()


class _UserConfigProxy:
    """
    Forwards everything to the real UserConfig but also answers getCurrentAccount(),
    which vanilla UserConfig does not expose (plugins rely on it).
    """

    def __init__(self, uc, account):
        self.__dict__["_uc"] = uc
        self.__dict__["_account"] = account

    def getCurrentAccount(self):
        return self.__dict__["_account"]

    def get_current_account(self):
        return self.__dict__["_account"]

    def __getattr__(self, name):
        return getattr(self.__dict__["_uc"], name)


def get_user_config():
    uc = PluginUtils.getUserConfig()
    return _UserConfigProxy(uc, PluginUtils.getCurrentAccount())


class _Runnable(dynamic_proxy(Runnable)):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.fn()
        except Exception as e:
            from android_utils import log
            log(e)


def run_on_queue(fn):
    """Run fn on a background worker queue (off the UI thread)."""
    if fn is not None:
        PluginUtils.runOnQueue(_Runnable(fn))


def send_document(dialog_id, file_path, caption="", replyToMsg=None, replyToTopMsg=None, replyQuote=None):
    """Send a local file as a document to a dialog. Reply/quote args are optional."""
    PluginUtils.sendDocument(
        int(dialog_id), str(file_path), caption if caption is not None else "",
        replyToMsg, replyToTopMsg, replyQuote)
