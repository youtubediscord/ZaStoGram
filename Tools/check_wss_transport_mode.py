#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
PROXY_SETTINGS = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxySettingsActivity.java"
LAUNCH_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java"
PROXY_DIAGNOSTICS = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckDiagnostics.java"
BOT_WEBVIEW = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java"
WRAPPER_CPP = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
CONNECTION_CPP = ROOT / "TMessagesProj/jni/tgnet/Connection.cpp"
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
WSS_H = ROOT / "TMessagesProj/jni/tgnet/WssTransport.h"
WSS_CPP = ROOT / "TMessagesProj/jni/tgnet/WssTransport.cpp"
CMAKE = ROOT / "TMessagesProj/jni/CMakeLists.txt"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    shared_config = text(SHARED_CONFIG)
    connections = text(CONNECTIONS_JAVA)
    proxy_list = text(PROXY_LIST)
    proxy_settings = text(PROXY_SETTINGS)
    launch_activity = text(LAUNCH_ACTIVITY)
    proxy_diagnostics = text(PROXY_DIAGNOSTICS)
    bot_webview = text(BOT_WEBVIEW)
    wrapper = text(WRAPPER_CPP)
    manager_cpp = text(MANAGER_CPP)
    manager_h = text(MANAGER_H)
    connection_cpp = text(CONNECTION_CPP)
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)
    cmake = text(CMAKE)
    wss_h = text(WSS_H) if WSS_H.exists() else ""
    wss_cpp = text(WSS_CPP) if WSS_CPP.exists() else ""
    mini_bridge = text(ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/WssMiniAppProxyBridge.java")

    require("PROXY_SCHEMA_V3" in shared_config, "proxy list schema must persist WSS transport fields separately from SOCKS5/MTProto")
    require("TRANSPORT_WSS_OFFICIAL" in shared_config and "TRANSPORT_WSS_CUSTOM" in shared_config and "TRANSPORT_WSS_SOCKS5" in shared_config, "SharedConfig must keep legacy WSS mode constants for migration")
    require("mode == TRANSPORT_WSS_SOCKS5" in shared_config and "return TRANSPORT_WSS_CUSTOM" in shared_config, "legacy SOCKS5 WSS mode must normalize to custom WSS")
    require("mode >= TRANSPORT_LEGACY_PROXY && mode <= TRANSPORT_WSS_SOCKS5" in shared_config, "official WSS mode must remain a valid native transport")
    require("wss_default_applied" in shared_config and "wssTransportMode = TRANSPORT_WSS_OFFICIAL" in shared_config, "first run must default to official Telegram WSS")
    require("wssHost" in shared_config and "wssPath" in shared_config and "wssUseForMiniApps" in shared_config, "ProxyInfo must persist custom WSS endpoint and miniapp routing intent")
    require("wssLocalProxyEnabled" not in shared_config and "saveWssLocalBridgeProxy" not in shared_config, "WSS transport must not persist a fake local loopback proxy row")
    require("isWssTransport()" in shared_config and "isSocks5OverWss()" in shared_config, "ProxyInfo must distinguish WSS from legacy proxy modes")

    require("WSS_TRANSPORT_OFFICIAL" in connections and "setWssTransportSettings" in connections, "Java ConnectionsManager must expose WSS constants and setter")
    require("native_setWssTransportSettings" in connections, "Java must wire WSS settings into JNI separately from proxy settings")
    require("resolveWssTransportMode" in connections, "Java must normalize WSS mode before native calls")
    require("resolveWssSocksProxy" in connections and "SharedConfig.currentWssSocksProxy" in connections and "mode == WSS_TRANSPORT_OFF" in connections and "mode != WSS_TRANSPORT_SOCKS5" not in connections, "WSS must reuse the selected SOCKS5 upstream for every enabled WSS mode and ignore MTProxy secrets")
    require("wssSocksHost" in connections and "wssSocksUsername" in connections and "wssSocksPassword" in connections, "Java WSS settings must pass selected SOCKS5 upstream credentials separately from WSS gateway settings")

    require("wssTransportModeRow" in proxy_list and "wssCustomGatewayRow" in proxy_list, "Proxy list UI must show a separate WSS transport section")
    require("R.string.WssTransportMode" in proxy_list and "R.string.WssTransportInfo" in proxy_list, "Proxy list UI must label WSS as a separate transport mode")
    require("R.string.ProxyConnections" in proxy_list and "R.string.WssTransportHeader" in proxy_list, "proxy UI must keep WSS rows apart from normal proxy connections")
    wss_options = proxy_list.split("private static final int[] WSS_TRANSPORT_OPTIONS", 1)[1].split("};", 1)[0]
    wss_labels = proxy_list.split("private String[] getWssTransportModeLabels", 1)[1].split("};", 1)[0]
    require("WSS_TRANSPORT_OPTIONS" in proxy_list and "ConnectionsManager.setWssTransportSettings" in proxy_list, "changing WSS mode in GUI must re-apply native transport settings")
    require("ConnectionsManager.WSS_TRANSPORT_OFFICIAL" in wss_options and "WssTransportOfficial" in wss_labels, "official WSS must be exposed as a visible transport mode")
    require("ConnectionsManager.WSS_TRANSPORT_SOCKS5" not in wss_options and "WssTransportSocks5" not in wss_labels, "SOCKS5 must be a selectable WSS upstream, not a separate WSS transport mode")
    require("openWssGatewaySettingsIfNeeded" in proxy_list and "ProxySettingsActivity.createWssGateway(mode)" in proxy_list, "selecting custom WSS must open the gateway editor instead of enabling native WSS directly")
    require("getEffectiveWssTransportMode" in proxy_list and "TextUtils.isEmpty(SharedConfig.wssHost)" in proxy_list and "return ConnectionsManager.WSS_TRANSPORT_OFF" in proxy_list, "saved custom WSS with an empty gateway must behave as off in the UI")
    require("disableLegacyProxyForWss" in proxy_list and "ConnectionsManager.setProxySettings(false" in proxy_list, "enabling WSS must disable the legacy proxy connection path so MTProxy cannot keep connecting")
    require("isWssTransportSelected()" in proxy_list and "useProxyRow = -1" in proxy_list and "mtProxySoftMuxRow = -1" in proxy_list, "proxy UI must hide legacy proxy toggles and MTProxy tuning while WSS transport is selected")
    require("if (wssTransportSelected)" in proxy_list and "isPlainSocksProxy" in proxy_list and "wss_socks_upstream" in proxy_list, "WSS UI must keep the SOCKS5 proxy list visible for every WSS mode while filtering out MTProxy entries")
    require("isProxyActiveForCurrentMode(currentInfo)" in proxy_list and "SharedConfig.currentWssSocksProxy == info" in proxy_list, "WSS SOCKS selection status must not depend on legacy proxy_enabled")
    require("clearSelectedWssSocksProxy" in proxy_list and "SharedConfig.currentWssSocksProxy == info" in proxy_list, "clicking the selected WSS SOCKS upstream again must clear it instead of leaving a stuck upstream selected")
    require("actionBar.setSubtitle(getString(R.string.WssTransportHeader)" in proxy_list and "ProxyCheckDiagnostics.headerStatusText" in proxy_list, "proxy UI header must show WSS status instead of legacy proxy status while WSS is selected")
    require("isWssTransportSelected()" in proxy_list and "isPlainSocksProxy" in proxy_list, "proxy UI must expose selected SOCKS5 proxies for every WSS mode without showing MTProxy entries")
    require("WssSocksUpstreamHeader" in proxy_list and "WssSocksUpstreamInfo" in proxy_list, "proxy UI must label the SOCKS5 list as WSS upstream, not as the legacy proxy mode")
    require("ProxySettingsActivity.createWssSocksUpstream()" in proxy_list and "ProxySettingsActivity.createWssSocksUpstream(currentInfo)" in proxy_list, "adding or editing a WSS SOCKS5 upstream must open a SOCKS-only proxy editor")
    require("HeaderStatusTitle" in proxy_diagnostics and "headerStatusTitle(" in proxy_diagnostics, "proxy diagnostics must expose a resource-backed header title for global action-bar status")
    require("ProxyCheckDiagnostics.headerStatusTitle" in launch_activity and "title = proxyStatusTitle.key" in launch_activity and "titleId = proxyStatusTitle.resId" in launch_activity, "main screen proxy overlay title must use the same proxy diagnostics as the proxy settings header")
    require('title = "ConnectingToProxyWithDots"' not in launch_activity, "main screen must not show the generic ConnectingToProxyWithDots title for proxy connection state")

    require("TYPE_WSS" in proxy_settings and "UseProxyWss" in proxy_settings, "proxy detail UI must offer WSS as a different proxy type")
    require("FIELD_WSS_PATH" in proxy_settings and "FIELD_WSS_HOST" in proxy_settings, "WSS detail UI must expose host/path separately from MTProxy secret")
    require("createWssGateway(int mode)" in proxy_settings and "wssEditorTransportMode" in proxy_settings, "WSS gateway editor must remember the pending custom/socks5 mode before it is saved globally")
    require("UseProxyWssInfo" in proxy_settings and "UseProxyTelegramInfoStealth" in proxy_settings, "WSS explanatory copy must be separate from MTProxy stealth copy")
    require("WssMiniAppProxyBridge.ensureStartedForProxySettings()" not in proxy_settings and "SharedConfig.setWssTransport(" in proxy_settings and "ConnectionsManager.setWssTransportSettings()" in proxy_settings, "saving a WSS gateway must save native WSS settings without starting a local proxy-settings bridge")
    require("createWssSocksUpstream()" in proxy_settings and "createWssSocksUpstream(SharedConfig.ProxyInfo proxyInfo)" in proxy_settings and "proxyTypeLocked" in proxy_settings and "saveAsWssSocksUpstream" in proxy_settings, "WSS SOCKS5 upstream editor must hide MTProxy choices and avoid enabling legacy proxy mode")
    require("ConnectionsManager.setWssTransportSettings()" in proxy_settings and "ConnectionsManager.setProxySettings(enabled" in proxy_settings, "saving a WSS SOCKS5 upstream must reapply WSS without starting legacy proxy mode")

    require('native_setWssTransportSettings", "(IIILjava/lang/String;ILjava/lang/String;ZLjava/lang/String;ILjava/lang/String;Ljava/lang/String;ZZ)V"' in wrapper, "JNI signature must carry WSS gateway plus selected SOCKS5 upstream settings")
    require("void setWssTransportSettings" in manager_h and "wssTransportMode" in manager_h and "wssSocksHost" in manager_h, "native manager must store WSS transport and selected SOCKS5 upstream settings")
    require("wssTransportChanged" in manager_cpp and "suspendConnections" in manager_cpp, "native manager must reconnect when WSS transport changes")

    require("WssTransport.cpp" in cmake and "tgnet/WssTransport.cpp" in cmake, "CMake must compile the native WSS transport module")
    require("class WssTransport" in wss_h and "WssRouteConfig" in wss_h, "WSS module must provide an isolated transport class and route config")
    require("kws2.web.telegram.org" in wss_cpp and "kws4.web.telegram.org" in wss_cpp and "/apiws" in wss_cpp, "WSS module must include official Telegram WSS route catalog")
    require("dcId != 2 && dcId != 4" in wss_cpp and "fallback to TCP" in socket_cpp, "official WSS must only auto-route proven DC2/DC4 relays and fall back for other DCs")
    require("Sec-WebSocket-Protocol: binary" in wss_cpp and "Sec-WebSocket-Key" in wss_cpp, "WSS module must perform a real WebSocket upgrade")
    require("buildSocks5Connect" in wss_cpp and "writeWebSocketFrame(remoteOut, buildSocksConnect" in mini_bridge, "WSS paths must include SOCKS CONNECT framing for native and miniapp gateway paths")
    require("upstreamSocksEnabled" in wss_h and "buildSocks5Greeting" in wss_cpp and "buildSocks5PasswordAuth" in wss_cpp, "WSS module must tunnel through selected SOCKS5 after the WSS gateway connect")
    require("TcpSocksGreetingWrite" in wss_h and "wss_tcp_socks" in wss_cpp, "WSS module must support selected SOCKS5 as the TCP upstream before TLS/WebSocket for official/custom WSS")
    require("SSL_connect" in wss_cpp and "SSL_read" in wss_cpp and "SSL_write" in wss_cpp, "WSS transport must use native TLS instead of FakeTLS or Python")

    require("openConnection(hostAddress, hostPort, secret, ipv6 != 0" in connection_cpp and "getDatacenterId()" in connection_cpp and "isMediaConnection" in connection_cpp, "Connection must pass DC/media metadata into the socket transport")
    require("isCurrentTransportWss()" in socket_h and "stateMachine.wss.transport" in socket_cpp, "ConnectionSocket must own WSS state separately from MTProxy state")
    require("wss_startup" in socket_cpp and "currentWssTransport->connect" in socket_cpp and "currentWssTransport->sendFrame" in socket_cpp, "ConnectionSocket must route connect/write/read through WSS when selected")
    require("manager.wssSocksHost" in socket_cpp and "manager.wssSocksUsername" in socket_cpp and "manager.wssSocksPassword" in socket_cpp and "manager.wssSocksEnabled" in socket_cpp and "wss_startup connect_via_socks" in socket_cpp, "ConnectionSocket WSS route must pass and connect through selected SOCKS5 upstream settings")
    require("fallback_to_socks" in socket_cpp and "currentSocksUsername = wssFallbackProxyUsername" in socket_cpp and "currentSocksPassword = wssFallbackProxyPassword" in socket_cpp, "official WSS without a stable DC relay must use the selected SOCKS fallback instead of silent direct TCP")
    require("wss_startup connect_start" in socket_cpp and "mtproxy_startup connect_start" in socket_cpp, "ConnectionSocket logs must not label WSS connects as MTProxy connects")
    require("forceProxyLikeInitForWss" in connection_cpp, "WSS mode must force the first MTProto init to carry dc_id without requiring an MTProxy secret")

    require("applyMiniAppWssProxyIfNeeded" in bot_webview and "wssUseForMiniApps" in bot_webview, "Bot miniapp WebView must have an explicit hook for WSS proxy routing")
    selected_socks_section = mini_bridge.split("private static SocksProxyConfig selectedSocksProxy()", 1)[1].split("public static int ensureStarted()", 1)[0]
    require("SharedConfig.wssTransportMode == SharedConfig.TRANSPORT_WSS_SOCKS5" not in mini_bridge and "mode == SharedConfig.TRANSPORT_WSS_CUSTOM" in mini_bridge and "selectedSocksProxy().enabled" in mini_bridge and "SharedConfig.currentWssSocksProxy" in selected_socks_section and "SharedConfig.currentProxy" not in selected_socks_section, "miniapp WSS proxy must be an on/off toggle that reuses the selected WSS SOCKS upstream")
    require("direct_upstream_connect_ok" in mini_bridge and "readRawSocksGreetingResponse" in mini_bridge and "bridgeRaw" in mini_bridge, "miniapp toggle must support official WSS with selected SOCKS without pretending official WSS is a SOCKS gateway")

    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        for key in (
            "WssTransportHeader",
            "WssTransportMode",
            "WssTransportOff",
            "WssTransportOfficial",
            "WssTransportCustom",
            "WssTransportInfo",
            "UseProxyWss",
            "UseProxyWssHost",
            "UseProxyWssPath",
            "UseProxyWssMiniApps",
            "UseProxyWssInfo",
            "WssSocksUpstreamHeader",
            "WssSocksUpstreamInfo",
        ):
            require(f'name="{key}"' in source, f"{path.name} must define {key}")

    print("WSS transport mode guard passed.")


if __name__ == "__main__":
    main()
