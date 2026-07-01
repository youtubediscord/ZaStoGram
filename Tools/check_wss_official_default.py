#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
PROXY_SETTINGS = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxySettingsActivity.java"
WSS_CPP = ROOT / "TMessagesProj/jni/tgnet/WssTransport.cpp"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def section(source: str, start: str, end: str) -> str:
    require(start in source, f"missing section start: {start}")
    tail = source.split(start, 1)[1]
    require(end in tail, f"missing section end after {start}: {end}")
    return tail.split(end, 1)[0]


def main() -> None:
    shared_config = text(SHARED_CONFIG)
    connections = text(CONNECTIONS)
    proxy_list = text(PROXY_LIST)
    proxy_settings = text(PROXY_SETTINGS)
    wss_cpp = text(WSS_CPP)

    normalize = section(shared_config, "public static int normalizeWssTransportMode", "public static String normalizeWssPath")
    load_config = section(shared_config, "public static void loadConfig()", "if (passcodeHash.length() > 0")
    wss_options = section(proxy_list, "private static final int[] WSS_TRANSPORT_OPTIONS", "};")
    wss_labels = section(proxy_list, "private String[] getWssTransportModeLabels", "};")
    resolve_mode = section(connections, "private static int resolveWssTransportMode()", "private static class WssSocksProxy")
    wss_save = section(proxy_settings, "if (currentType == TYPE_WSS)", "currentProxyInfo.address")

    require("mode >= TRANSPORT_LEGACY_PROXY && mode <= TRANSPORT_WSS_SOCKS5" in normalize,
            "official WSS must remain a valid transport mode, not normalize to legacy proxy")
    require("wss_default_applied" in load_config and "wssTransportMode = TRANSPORT_WSS_OFFICIAL" in load_config,
            "first run must default to official Telegram WSS")
    require("ConnectionsManager.WSS_TRANSPORT_OFFICIAL" in wss_options,
            "WSS mode chooser must expose official Telegram WSS")
    require("WssTransportOfficial" in wss_labels,
            "WSS mode labels must include official Telegram WSS")
    require("WSS_TRANSPORT_OFFICIAL" not in resolve_mode or "return WSS_TRANSPORT_OFF" not in resolve_mode.split("WSS_TRANSPORT_OFFICIAL", 1)[-1],
            "Java resolver must not disable official WSS before native")
    require("wssLocalProxyEnabled" not in shared_config and "saveWssLocalBridgeProxy" not in shared_config,
            "official WSS default must not depend on a local proxy row")
    require("WssMiniAppProxyBridge.ensureStartedForProxySettings()" not in wss_save,
            "saving WSS settings must not start a local proxy-settings bridge")
    require("SharedConfig.setWssTransport(" in wss_save and "ConnectionsManager.setWssTransportSettings()" in wss_save,
            "WSS gateway editor must save native WSS settings")
    require("kws2.web.telegram.org" in wss_cpp and "kws4.web.telegram.org" in wss_cpp and "dcId != 2 && dcId != 4" in wss_cpp,
            "native official WSS route must target Telegram DC2/DC4 web relays only")

    print("WSS official default guard passed.")


if __name__ == "__main__":
    main()
