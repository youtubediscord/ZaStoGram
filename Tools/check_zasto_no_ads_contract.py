#!/usr/bin/env python3
"""Static guard for ZaStoGram no-ads behavior."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
ZASTO_PRIVACY = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ZaStoPrivacy.java"
MESSAGES_CONTROLLER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java"
CHAT_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java"
VIDEO_ADS = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/video/VideoAds.java"
DIALOGS_SEARCH_ADAPTER = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Adapters/DialogsSearchAdapter.java"
DIALOGS_ADAPTER = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Adapters/DialogsAdapter.java"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        return ""
    brace = text.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return ""


def main() -> int:
    zasto_privacy = read(ZASTO_PRIVACY)
    messages_controller = read(MESSAGES_CONTROLLER)
    chat_activity = read(CHAT_ACTIVITY)
    video_ads = read(VIDEO_ADS)
    dialogs_search_adapter = read(DIALOGS_SEARCH_ADAPTER)
    dialogs_adapter = read(DIALOGS_ADAPTER)
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require(
        "public static final boolean DISABLE_ADS = true;" in zasto_privacy,
        "ZaStoPrivacy must expose DISABLE_ADS enabled by default",
    )

    get_sponsored = method_body(messages_controller, "public SponsoredMessagesInfo getSponsoredMessages(long dialogId)")
    check_promo = method_body(messages_controller, "private void checkPromoInfoInternal(boolean reset)")
    require(
        "ZaStoPrivacy.DISABLE_ADS" in check_promo
        and "promoDialogId = 0" in check_promo
        and check_promo.find("ZaStoPrivacy.DISABLE_ADS") < check_promo.find("new TLRPC.TL_help_getPromoData"),
        "MessagesController.checkPromoInfoInternal must return before the promo-data network request",
    )
    require(
        "ZaStoPrivacy.DISABLE_ADS" in get_sponsored
        and "sponsoredMessages.remove(dialogId)" in get_sponsored
        and get_sponsored.find("ZaStoPrivacy.DISABLE_ADS") < get_sponsored.find("new TLRPC.TL_messages_getSponsoredMessages"),
        "MessagesController.getSponsoredMessages must return before the sponsored network request",
    )
    require(
        re.search(r"public\s+boolean\s+isSponsoredDisabled\s*\(\s*\)\s*\{\s*if\s*\(ZaStoPrivacy\.DISABLE_ADS\)\s+return\s+true;", messages_controller) is not None,
        "MessagesController.isSponsoredDisabled must report disabled ads while DISABLE_ADS is enabled",
    )
    require(
        re.search(r"public\s+boolean\s+isPromoDialog\s*\([^)]*\)\s*\{\s*if\s*\(ZaStoPrivacy\.DISABLE_ADS\)\s+return\s+false;", messages_controller) is not None,
        "MessagesController.isPromoDialog must hide proxy/PSA promo dialogs while DISABLE_ADS is enabled",
    )

    add_sponsored = method_body(chat_activity, "private void addSponsoredMessages(boolean animated)")
    require(
        "ZaStoPrivacy.DISABLE_ADS" in add_sponsored
        and add_sponsored.find("ZaStoPrivacy.DISABLE_ADS") < add_sponsored.find("getMessagesController().getSponsoredMessages"),
        "ChatActivity.addSponsoredMessages must return before adding channel/bot sponsored messages",
    )
    update_top_panel = method_body(chat_activity, "public void updateTopPanel(boolean animated)")
    require(
        "ZaStoPrivacy.DISABLE_ADS" in update_top_panel,
        "ChatActivity top panel must not show bot sponsored ads while DISABLE_ADS is enabled",
    )
    require(
        "if (org.telegram.messenger.ZaStoPrivacy.DISABLE_ADS) return;" in method_body(chat_activity, "public void logSponsoredClicked")
        and "if (org.telegram.messenger.ZaStoPrivacy.DISABLE_ADS) return;" in method_body(chat_activity, "private void markSponsoredAsRead"),
        "ChatActivity must not log sponsored impressions/clicks while DISABLE_ADS is enabled",
    )

    load_video_ads = method_body(video_ads, "private void load()")
    require(
        "ZaStoPrivacy.DISABLE_ADS" in video_ads
        and "loaded = true" in load_video_ads
        and load_video_ads.find("ZaStoPrivacy.DISABLE_ADS") < load_video_ads.find("new TLRPC.TL_messages_getSponsoredMessages"),
        "VideoAds.load must complete without a sponsored network request while DISABLE_ADS is enabled",
    )
    require(
        "if (ZaStoPrivacy.DISABLE_ADS || ad == null) return;" in method_body(video_ads, "public void logSponsoredShown")
        and "if (ZaStoPrivacy.DISABLE_ADS || ad == null) return;" in method_body(video_ads, "public void logSponsoredClicked"),
        "VideoAds must not log sponsored impressions/clicks while DISABLE_ADS is enabled",
    )

    search_method = method_body(dialogs_search_adapter, "public void searchDialogs")
    require(
        "ZaStoPrivacy.DISABLE_ADS" in dialogs_search_adapter
        and "sponsoredPeers.clear()" in search_method
        and search_method.find("ZaStoPrivacy.DISABLE_ADS") < search_method.find("new TLRPC.TL_contacts_getSponsoredPeers"),
        "DialogsSearchAdapter must avoid sponsored peer requests while DISABLE_ADS is enabled",
    )
    require(
        "if (ZaStoPrivacy.DISABLE_ADS || sponsoredPeer == null) return;" in method_body(dialogs_search_adapter, "public void seenSponsoredPeer")
        and "if (ZaStoPrivacy.DISABLE_ADS || sponsoredPeer == null) return;" in method_body(dialogs_search_adapter, "public void clickedSponsoredPeer"),
        "DialogsSearchAdapter must not log sponsored peer impressions/clicks while DISABLE_ADS is enabled",
    )

    require(
        "ZaStoPrivacy.DISABLE_ADS" in dialogs_adapter
        and "return false;" in method_body(dialogs_adapter, "private boolean shouldShowZapretVpnSponsor"),
        "DialogsAdapter must hide the local Zapret VPN sponsor row while DISABLE_ADS is enabled",
    )
    require(
        "ZaStoPrivacy.DISABLE_ADS" in method_body(dialogs_adapter, "private ArrayList<TLRPC.Dialog> filterLegacyProxySponsorDialogs"),
        "DialogsAdapter must remove legacy Telegram proxy sponsor dialogs while DISABLE_ADS is enabled",
    )

    if failures:
        print("ZaSto no-ads contract failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("ZaSto no-ads contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
