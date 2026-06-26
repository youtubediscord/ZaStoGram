#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PROXY_SETTINGS = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxySettingsActivity.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def fail(message: str) -> None:
    raise SystemExit(f"proxy link input check failed: {message}")


def slice_between(text: str, start: str, end: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        fail(f"missing block start {start!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        fail(f"missing block end {end!r}")
    return text[start_index:end_index]


def main() -> int:
    java = PROXY_SETTINGS.read_text(encoding="utf-8")
    strings = STRINGS.read_text(encoding="utf-8")
    strings_ru = STRINGS_RU.read_text(encoding="utf-8")

    if 'name="UseProxyLink"' not in strings:
        fail("base strings must define UseProxyLink")
    if 'name="UseProxyLink"' not in strings_ru:
        fail("Russian strings must define UseProxyLink")

    for needle in (
        "private EditTextBoldCursor quickProxyLinkField;",
        "private boolean ignoreQuickProxyLinkChange;",
        "quickProxyLinkField.setHintText(LocaleController.getString(R.string.UseProxyLink));",
        "applyParsedProxyLink(parsedProxyLink, true);",
    ):
        if needle not in java:
            fail(f"ProxySettingsActivity missing {needle}")

    if "private static final class ParsedProxyLink" not in java:
        fail("proxy link parser must return a structured ParsedProxyLink")

    parse_body = slice_between(
        java,
        "private ParsedProxyLink parseProxyLink(String text)",
        "private void applyParsedProxyLink",
    )
    for link_marker in ("t.me/socks?", "tg://socks?", "t.me/proxy?", "tg://proxy?", "zastogram://wss?", "tg://wss?"):
        if link_marker not in parse_body:
            fail(f"parser must recognize {link_marker}")
    if "split(\"=\", 2)" not in parse_body:
        fail("parser must split query pairs at the first '=' only")
    if "URLDecoder.decode" not in parse_body:
        fail("parser must URL-decode server, port, secret, user and pass values")

    apply_body = slice_between(
        java,
        "private void applyParsedProxyLink(ParsedProxyLink parsedProxyLink, boolean animated)",
        "private void updatePasteCell()",
    )
    for assignment in (
        "inputFields[i].setText(parsedProxyLink.fields[i]);",
        "setProxyType(parsedProxyLink.type, animated",
        "inputFields[focusField].setSelection(inputFields[focusField].length());",
        "AndroidUtilities.hideKeyboard(inputFieldsContainer.findFocus());",
    ):
        if assignment not in apply_body:
            fail(f"link application must contain {assignment}")

    paste_body = slice_between(java, "private void updatePasteCell()", "private void setShareDoneEnabled")
    if "ParsedProxyLink parsedProxyLink = parseProxyLink(clipText);" not in paste_body:
        fail("clipboard paste flow must reuse the same parser as the visible link field")
    if "pasteType = parsedProxyLink.type;" not in paste_body or "pasteFields = parsedProxyLink.fields;" not in paste_body:
        fail("clipboard paste flow must use ParsedProxyLink fields")

    print("proxy link input check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
