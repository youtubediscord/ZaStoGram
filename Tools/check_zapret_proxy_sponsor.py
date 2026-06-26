#!/usr/bin/env python3
"""Static guard for the Zapret VPN sponsor row and free proxy links."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DIALOGS_ADAPTER = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Adapters/DialogsAdapter.java"
DIALOGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/DialogsActivity.java"
SETTINGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java"
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"


EXPECTED_STRINGS = {
    "ZapretVpnSponsorTitle": "Zapret VPNs",
    "ZapretVpnSponsorSubtitle": "Спонсор прокси",
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
        "DialogsAdapter must define a dedicated sponsor view type",
    )
    require(
        "shouldShowZapretVpnSponsor()" in dialogs_adapter,
        "DialogsAdapter must gate the sponsor row to the default chat list",
    )
    require(
        "SharedConfig.showZapretVpnSponsor" in dialogs_adapter,
        "DialogsAdapter must honor the hide setting",
    )
    require(
        "getString(R.string.ZapretVpnSponsorTitle)" in dialogs_adapter
        and "getString(R.string.ZapretVpnSponsorSubtitle)" in dialogs_adapter,
        "Sponsor row must use the Zapret VPN title and proxy sponsor subtitle",
    )
    require(
        "isZapretVpnSponsor(position)" in dialogs_activity
        and 'Browser.openUrl(getContext(), "https://t.me/zapretvpns_bot")' in dialogs_activity,
        "DialogsActivity must open the sponsor bot from the synthetic chat row",
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


if __name__ == "__main__":
    sys.exit(main())
