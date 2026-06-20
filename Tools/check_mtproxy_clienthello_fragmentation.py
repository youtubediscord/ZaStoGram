#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
WRAPPER_CPP = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"
COLLECT = ROOT / "Tools/collect_mtproxy_logs.ps1"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)
    manager_cpp = text(MANAGER_CPP)
    manager_h = text(MANAGER_H)
    wrapper_cpp = text(WRAPPER_CPP)
    connections_java = text(CONNECTIONS_JAVA)
    shared_config = text(SHARED_CONFIG)
    proxy_list = text(PROXY_LIST)
    collect = text(COLLECT)

    require(
        "mtProxyClientHelloFragmentation" in shared_config
        and "mtProxyClientHelloFragmentation" in proxy_list
        and "R.string.MtProxyClientHelloFragmentation" in proxy_list,
        "proxy settings UI must expose a global ClientHello fragmentation toggle",
    )
    require(
        "MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF" in connections_java
        and "resolveMtProxyClientHelloFragmentationMode()" in connections_java,
        "Java must resolve a stable ClientHello fragmentation mode from SharedConfig",
    )
    require(
        re.search(r"native_setProxySettings\(.*mtProxyTlsProfile,\s*mtProxyClientHelloFragmentation", connections_java, re.S),
        "real proxy settings must pass ClientHello fragmentation mode into native",
    )
    require(
        re.search(r"native_checkProxy\(.*mtProxyTlsProfile,\s*mtProxyClientHelloFragmentation", connections_java, re.S),
        "proxy checks must use the same ClientHello fragmentation mode as real connections",
    )
    require(
        "jint mtProxyClientHelloFragmentation" in wrapper_cpp
        and "Ljava/lang/String;II)V" in wrapper_cpp
        and "ILorg/telegram/tgnet/RequestTimeDelegate;)J" in wrapper_cpp,
        "JNI signatures must carry the extra ClientHello fragmentation integer",
    )
    require(
        "int32_t proxyClientHelloFragmentation" in manager_h
        and "clientHelloFragmentationChanged" in manager_cpp
        and "proxyClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation" in manager_cpp,
        "ConnectionsManager must store the fragmentation mode and reconnect when it changes",
    )
    require(
        "mtProxyClientHelloFragmentation" in manager_cpp
        and "proxyCheckInfo->mtProxyClientHelloFragmentation" in manager_cpp,
        "proxy-check native state must receive the fragmentation mode",
    )
    require(
        "overrideProxyClientHelloFragmentation" in socket_h
        and "currentClientHelloFragmentation" in socket_h
        and "setOverrideProxy" in socket_h,
        "ConnectionSocket must carry fragmentation mode for normal and override proxy paths",
    )
    require(
        "sendPendingClientHelloFragment" in socket_cpp
        and "mtproxy_startup client_hello_fragment" in socket_cpp
        and "MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT" in socket_cpp,
        "ClientHello send path must implement and log soft fragmentation as a separate layer",
    )
    require(
        "client_hello_fragment" in collect
        and "$textFiles = @(Join-Path $sessionDir \"logcat.txt\")" in collect,
        "collector must include fragmentation markers and analyze live logcat without old device-log contamination",
    )
    require(
        'name="MtProxyClientHelloFragmentation"' in text(STRINGS)
        and 'name="MtProxyClientHelloFragmentation"' in text(STRINGS_RU),
        "ClientHello fragmentation UI strings must exist in base and Russian resources",
    )

    print("MTProxy ClientHello fragmentation guard passed.")


if __name__ == "__main__":
    main()
