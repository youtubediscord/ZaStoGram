#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    connections = text(CONNECTIONS_JAVA)
    proxy_list = text(PROXY_LIST)

    require(
        "MT_PROXY_TLS_PROFILE_AUTO" in connections
        and "MT_PROXY_TLS_PROFILE_OVERRIDE" in connections
        and "stableMtProxyTlsHash" in connections,
        "Auto mode must keep the existing sticky per-endpoint/profile selection",
    )
    require(
        "getMtProxyTlsProfileOverride()" in connections
        and "setMtProxyTlsProfileOverride" in connections
        and "normalizeMtProxyTlsProfileOverride" in connections,
        "ConnectionsManager must expose safe getters/setters for manual JA4 profile override",
    )
    require(
        re.search(r"preferences\.edit\(\)\.putInt\(MT_PROXY_TLS_PROFILE_OVERRIDE, profile\)\.apply\(\)", connections),
        "manual JA4 profile override must be persisted in the existing profile preferences",
    )
    require(
        "tlsProfileRow" in proxy_list
        and "R.string.MtProxyTlsProfile" in proxy_list
        and "R.string.MtProxyTlsProfileAuto" in proxy_list
        and "R.string.MtProxyTlsProfileAutoRotate" in proxy_list
        and "ConnectionsManager.setMtProxyTlsProfileOverride" in proxy_list,
        "proxy settings UI must expose Auto, Auto rotate, and manual JA4 profile selection",
    )
    require(
        "MT_PROXY_TLS_PROFILE_ANDROID_CHROME" in proxy_list
        and "MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID" in proxy_list
        and "MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP" in proxy_list,
        "JA4 UI must include the Android profile family for the default testing path",
    )
    require(
        "ConnectionsManager.setProxySettings(true" in proxy_list,
        "changing JA4 profile in UI must re-apply current proxy settings immediately",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        for key in [
            "MtProxyTlsProfile",
            "MtProxyTlsProfileInfo",
            "MtProxyTlsProfileAuto",
            "MtProxyTlsProfileAutoRotate",
            "MtProxyTlsProfileAndroidChrome",
            "MtProxyTlsProfileChromeModern",
            "MtProxyTlsProfileFirefoxAndroid",
            "MtProxyTlsProfileAndroidOkHttp",
            "MtProxyTlsProfileFirefox",
            "MtProxyTlsProfileYandex",
        ]:
            require(f'name="{key}"' in source, f"{path.name} must define {key}")

    print("MTProxy TLS profile UI guard passed.")


if __name__ == "__main__":
    main()
