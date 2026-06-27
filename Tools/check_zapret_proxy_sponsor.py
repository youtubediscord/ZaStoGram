#!/usr/bin/env python3
"""Static guard for the Zapret VPN real sponsor dialog and free proxy links."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DIALOGS_ADAPTER = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Adapters/DialogsAdapter.java"
DIALOGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/DialogsActivity.java"
DIALOG_CELL = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Cells/DialogCell.java"
SETTINGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java"
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"


EXPECTED_STRINGS = {
    "ZapretVpnSponsorSetting": "Показывать спонсора прокси",
    "FreeProxyChannels": "Бесплатные прокси",
    "FreeProxyMtProxyEveryday": "MTProxy everyday",
    "FreeProxyProxyMtProto": "Proxy MTProto",
    "FreeProxyProxyFreeRu": "Proxy Free Ru",
    "FreeProxyTgMtProxyLol": "TG MTProxy LOL",
    "FreeProxyMemtproxy": "memtproxy",
    "FreeProxyTProxyRu": "TProxy RU",
    "FreeProxyProxyFreeMTProto": "Proxy Free MTProto",
    "FreeProxyTelMTProto": "Tel MTProto",
}

EXPECTED_LINKS = {
    28: ("FreeProxyMtProxyEveryday", "https://t.me/MTProxy_everyday"),
    29: ("FreeProxyProxyMtProto", "https://t.me/ProxyMTProto"),
    30: ("FreeProxyProxyFreeRu", "https://t.me/ProxyFree_Ru"),
    31: ("FreeProxyTgMtProxyLol", "https://t.me/tgmtproxylol"),
    32: ("FreeProxyMemtproxy", "https://t.me/memtproxy"),
    33: ("FreeProxyTProxyRu", "https://t.me/TProxyRU"),
    34: ("FreeProxyProxyFreeMTProto", "https://t.me/ProxyFreeMTProto"),
    35: ("FreeProxyTelMTProto", "https://t.me/TelMTProto"),
}


def main() -> int:
    dialogs_adapter = DIALOGS_ADAPTER.read_text(encoding="utf-8")
    dialogs_activity = DIALOGS_ACTIVITY.read_text(encoding="utf-8")
    dialog_cell = DIALOG_CELL.read_text(encoding="utf-8")
    settings_activity = SETTINGS_ACTIVITY.read_text(encoding="utf-8")
    shared_config = SHARED_CONFIG.read_text(encoding="utf-8")
    strings = STRINGS.read_text(encoding="utf-8")
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    for name, value in EXPECTED_STRINGS.items():
        require(
            f'<string name="{name}">{value}</string>' in strings,
            f"Missing string resource {name}={value}",
        )

    require(
        "public static boolean showZapretVpnSponsor = true;" in shared_config,
        "SharedConfig must expose showZapretVpnSponsor defaulting to true",
    )
    require(
        'getBoolean("showZapretVpnSponsor", true)' in shared_config,
        "showZapretVpnSponsor must load as enabled by default",
    )
    require(
        'putBoolean("showZapretVpnSponsor", showZapretVpnSponsor)' in shared_config,
        "showZapretVpnSponsor must be persisted",
    )

    require(
        "VIEW_TYPE_ZAPRET_VPN_SPONSOR" in dialogs_adapter,
        "Sponsor must use a stable dedicated item type",
    )
    require(
        "shouldShowZapretVpnSponsor()" in dialogs_adapter,
        "DialogsAdapter must gate the sponsor row to the default chat list",
    )
    require(
        'ZAPRET_VPN_SPONSOR_USERNAME = "zapretvpns_bot"' in dialogs_adapter,
        "DialogsAdapter must use the real Zapret VPNs username",
    )
    require(
        "filterLegacyProxySponsorDialogs(" in dialogs_adapter
        and "messagesController.promoDialogType == MessagesController.PROMO_TYPE_PROXY" in dialogs_adapter,
        "DialogsAdapter must remove the legacy Telegram proxy promo dialog",
    )
    require(
        "removeZapretVpnSponsorDialogFromArray(" in dialogs_adapter
        and "insertZapretVpnSponsorItem(" in dialogs_adapter
        and "isArchiveDialog(item.dialog)" in dialogs_adapter,
        "DialogsAdapter must keep a separate sponsor item below the archive row without replacing chats",
    )
    require(
        "SharedConfig.showZapretVpnSponsor" in dialogs_adapter,
        "DialogsAdapter must honor the hide setting",
    )
    is_sponsor_method = dialogs_adapter[
        dialogs_adapter.find("public boolean isZapretVpnSponsorDialog"):
        dialogs_adapter.find("private ArrayList<TLRPC.Dialog> filterLegacyProxySponsorDialogs")
    ]
    require(
        "!shouldShowZapretVpnSponsor()" in is_sponsor_method,
        "Sponsor row detection must turn off when the setting is hidden",
    )
    require(
        "DialogCell.CustomDialog" not in extract_zapret_adapter_region(dialogs_adapter)
        and "customDialog.name" not in extract_zapret_adapter_region(dialogs_adapter)
        and "customDialog.message" not in extract_zapret_adapter_region(dialogs_adapter),
        "Sponsor row must not be rendered as a fake CustomDialog",
    )
    require(
        "getUserNameResolver().resolve(ZAPRET_VPN_SPONSOR_USERNAME" in dialogs_adapter
        and "messagesController.dialogs_dict.get(dialogId)" in dialogs_adapter,
        "DialogsAdapter must resolve the username and prefer an existing real dialog",
    )
    require(
        "cell.setDialog(sponsorDialog, dialogsType, folderId)" in dialogs_adapter
        and "cell.setDialog(zapretVpnSponsorDialogId, null, 0, false, false)" in dialogs_adapter,
        "Sponsor row must bind either the real dialog or the resolved real peer, never a placeholder dialog",
    )
    require(
        "isZapretVpnSponsorDialog(position)" in dialogs_activity
        and "openByUserName(DialogsAdapter.ZAPRET_VPN_SPONSOR_USERNAME" in dialogs_activity
        and 'Browser.openUrl(getContext(), "https://t.me/zapretvpns_bot")' not in dialogs_activity,
        "DialogsActivity must open the sponsor through Telegram username resolution, not Browser.openUrl",
    )
    custom_dialog_start = dialog_cell.find("public void setDialog(CustomDialog dialog)")
    custom_dialog_end = dialog_cell.find("private void checkOnline()", custom_dialog_start)
    custom_dialog_body = dialog_cell[custom_dialog_start:custom_dialog_end]
    require(
        "currentDialogId = 0;" in custom_dialog_body
        and "message = null;" in custom_dialog_body
        and "user = null;" in custom_dialog_body
        and "chat = null;" in custom_dialog_body
        and "encryptedChat = null;" in custom_dialog_body,
        "DialogCell custom rows must clear recycled real-dialog state",
    )
    require(
        dialog_cell.count("customDialog = null;") >= 4,
        "DialogCell real chat/topic setters must clear recycled custom-dialog state",
    )
    real_dialog_start = dialog_cell.find("public void setDialog(TLRPC.Dialog dialog, int type, int folder)")
    real_dialog_end = dialog_cell.find("protected boolean drawLock2()", real_dialog_start)
    real_dialog_body = dialog_cell[real_dialog_start:real_dialog_end]
    require(
        "forumTopic = null;" in real_dialog_body
        and "isTopic = false;" in real_dialog_body
        and "isForum = false;" in real_dialog_body
        and "groupMessages = null;" in real_dialog_body,
        "DialogCell real dialog binding must clear recycled topic/folder state",
    )

    require(
        "items.add(UItem.asHeader(getString(R.string.FreeProxyChannels)))" in settings_activity,
        "Settings must include the FreeProxyChannels block",
    )
    require(
        re.search(
            r"SettingCell\.Factory\.of\(27,[^;]+getString\(R\.string\.ZapretVpnSponsorSetting\)[^;]+SharedConfig\.showZapretVpnSponsor",
            settings_activity,
            re.DOTALL,
        )
        is not None,
        "Settings must include a row that toggles the sponsor visibility",
    )
    require(
        "SharedConfig.showZapretVpnSponsor = !SharedConfig.showZapretVpnSponsor" in settings_activity
        and "SharedConfig.saveConfig()" in settings_activity,
        "Settings must toggle and persist sponsor visibility",
    )

    for item_id, (string_name, url) in EXPECTED_LINKS.items():
        require(
            re.search(
                rf"SettingCell\.Factory\.of\({item_id},[^;]+getString\(R\.string\.{string_name}\)\)",
                settings_activity,
                re.DOTALL,
            )
            is not None,
            f"Settings item {item_id} must use {string_name}",
        )
        require(
            re.search(
                rf"case {item_id}:\s+Browser\.openUrl\(getParentActivity\(\), \"{re.escape(url)}\"\);\s+break;",
                settings_activity,
                re.DOTALL,
            )
            is not None,
            f"Settings item {item_id} must open {url}",
        )

    if errors:
        print("Zapret proxy sponsor check failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Zapret proxy sponsor check passed")
    return 0


def extract_zapret_adapter_region(dialogs_adapter: str) -> str:
    start = dialogs_adapter.find("ZAPRET")
    if start < 0:
        return ""
    end = dialogs_adapter.find("case VIEW_TYPE_FORWARD_TO_STORIES_CELL", start)
    if end < 0:
        end = dialogs_adapter.find("case VIEW_TYPE_EMPTY", start)
    return dialogs_adapter[start:end]


if __name__ == "__main__":
    sys.exit(main())
