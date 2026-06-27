"""ui.alert — AlertDialogBuilder wrapping the fork's themed AlertDialog.Builder."""

from java import dynamic_proxy

from org.telegram.ui.ActionBar import AlertDialog

from android_utils import log
from client_utils import get_context


class _ButtonClick(dynamic_proxy(AlertDialog.OnButtonClickListener)):
    def __init__(self, builder, fn):
        super().__init__()
        self.builder = builder
        self.fn = fn

    def onClick(self, dialog, which):
        try:
            if self.fn is not None:
                # exteraGram convention: callback receives (builder, which) so it can dismiss().
                self.fn(self.builder, which)
        except Exception as e:
            log(e)


class AlertDialogBuilder:

    def __init__(self, context=None):
        if context is None:
            context = get_context()
        self._builder = AlertDialog.Builder(context)
        self._dialog = None

    def set_title(self, title):
        self._builder.setTitle(title)
        return self

    def set_message(self, message):
        self._builder.setMessage(message)
        return self

    def set_view(self, view):
        self._builder.setView(view)
        return self

    def set_positive_button(self, text, fn=None):
        self._builder.setPositiveButton(text, _ButtonClick(self, fn))
        return self

    def set_negative_button(self, text, fn=None):
        self._builder.setNegativeButton(text, _ButtonClick(self, fn))
        return self

    def set_neutral_button(self, text, fn=None):
        try:
            self._builder.setNeutralButton(text, _ButtonClick(self, fn))
        except Exception as e:
            log(e)
        return self

    def set_cancelable(self, value):
        try:
            self._builder.setCancelable(bool(value))
        except Exception:
            pass
        return self

    def create(self):
        self._dialog = self._builder.create()
        return self._dialog

    def show(self):
        self._dialog = self._builder.show()
        return self._dialog

    def dismiss(self):
        try:
            if self._dialog is not None:
                self._dialog.dismiss()
        except Exception:
            pass

    def get_dialog(self):
        return self._dialog

    def get_builder(self):
        return self._builder
