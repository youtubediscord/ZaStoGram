#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
WRAPPER_CPP = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
MACHINE_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocketStateMachine.h"
SHAPER_CPP = ROOT / "TMessagesProj/jni/tgnet/MtProxyDataPathShaper.cpp"
PROXY_CHECK = ROOT / "TMessagesProj/jni/tgnet/ProxyCheckInfo.h"
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
    wrapper = text(WRAPPER_CPP)
    manager_cpp = text(MANAGER_CPP)
    manager_h = text(MANAGER_H)
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)
    shaper_cpp = text(SHAPER_CPP)
    socket_state = socket_h + "\n" + text(MACHINE_H) + "\n" + socket_cpp
    proxy_check = text(PROXY_CHECK)

    require(
        "mtProxyStartupCoverMode" in shared_config
        and 'getInt("mtProxyStartupCoverMode", 0)' in shared_config
        and 'putInt("mtProxyStartupCoverMode", mtProxyStartupCoverMode)' in shared_config,
        "SharedConfig must persist Startup Cover mode",
    )
    require(
        "MT_PROXY_STARTUP_COVER_OFF" in connections
        and "MT_PROXY_STARTUP_COVER_SOFT" in connections
        and "MT_PROXY_STARTUP_COVER_STRICT" in connections
        and "resolveMtProxyStartupCoverMode()" in connections,
        "Java must expose Startup Cover constants and resolver",
    )
    require(
        "mtProxyStartupCoverRow" in proxy_list
        and "MT_PROXY_STARTUP_COVER_OPTIONS" in proxy_list
        and "getMtProxyStartupCoverLabels" in proxy_list
        and "SharedConfig.mtProxyStartupCoverMode" in proxy_list,
        "proxy settings UI must expose Startup Cover modes",
    )
    require(
        "mtProxyStartupCoverMode" in connections
        and "MtProxyOptions.resolve(proxyAddress, proxyPort, proxySecret)" in connections
        and "MtProxyOptions.resolve(address, port, secret)" in connections,
        "real proxy settings and proxy checks must pass Startup Cover through MtProxyOptions",
    )
    require(
        'native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;ILjava/lang/String;)V"' in wrapper
        and 'native_checkProxy", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;Lorg/telegram/tgnet/RequestTimeDelegate;)J"' in wrapper,
        "JNI signatures must carry Startup Cover through MtProxyOptions",
    )
    require(
        "MtProxyOptions proxyMtProxyOptions" in manager_h
        and "optionsChanged" in manager_cpp
        and "normalizeMtProxyOptions(options)" in manager_cpp,
        "native ConnectionsManager must store Startup Cover in MtProxyOptions and reconnect when it changes",
    )
    require(
        "MtProxyOptions mtProxyOptions" in proxy_check,
        "proxy checks must carry MtProxyOptions for same-path testing",
    )
    require(
        "overrideMtProxyOptions" in socket_h
        and "currentStartupCoverMode" in socket_state
        and "startupCoverStartTime" in socket_state
        and "startupCoverFrameCount" in socket_state,
        "ConnectionSocket must carry Startup Cover state",
    )
    require(
        "startMtProxyStartupCover" in socket_cpp
        and "effectiveMtProxyRecordSizingMode" in socket_cpp
        and "effectiveMtProxyTimingMode" in socket_cpp
        and "mtproxy_data startup_cover_start" in socket_cpp
        and "mtproxy_data startup_cover_end" in socket_cpp,
        "ConnectionSocket must apply and log Startup Cover only in the FakeTLS data path",
    )
    require(
        "server_hello_hmac_ok" in socket_cpp
        and "startMtProxyStartupCover();" in socket_cpp,
        "Startup Cover must start only after ServerHello/HMAC succeeds",
    )
    require(
        "mtProxyStartupCoverPolicy(currentSecretIsFakeTls, currentStartupCoverMode)" in socket_cpp
        and "policy.enabled" in socket_cpp
        and "!fakeTls || policy.mode == MT_PROXY_STARTUP_COVER_OFF" in shaper_cpp,
        "Startup Cover must be gated to FakeTLS and be fully off when disabled",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        for key in (
            "MtProxyStartupCover",
            "MtProxyStartupCoverInfo",
            "MtProxyStartupCoverOff",
            "MtProxyStartupCoverSoft",
            "MtProxyStartupCoverStrict",
        ):
            require(f'name="{key}"' in source, f"{path.name} must define {key}")

    print("MTProxy Startup Cover guard passed.")


if __name__ == "__main__":
    main()
