#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
FILE_LOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java"
FILE_UPLOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileUploadOperation.java"
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
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
    file_load = text(FILE_LOAD)
    file_upload = text(FILE_UPLOAD)
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)

    require(
        "MT_PROXY_TLS_PROFILE_AUTO_ROTATE" in connections,
        "ConnectionsManager must expose Auto rotate TLS profile mode",
    )
    require(
        "MtProxyTlsProfileAutoRotate" in proxy_list
        and "MT_PROXY_TLS_PROFILE_AUTO_ROTATE" in proxy_list,
        "proxy settings UI must expose Auto rotate as a selectable JA4 mode",
    )
    require(
        re.search(
            r"private static final int MT_PROXY_TLS_PROFILE_RANDOM_COUNT = 2;",
            connections,
        )
        and "return MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP;" not in connections,
        "stable Auto pool must exclude Android OkHttp until it is server-compatible",
    )
    require(
        "return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;" in connections
        and "return MT_PROXY_TLS_PROFILE_YANDEX;" in connections,
        "stable Auto pool must currently use Firefox Android and Yandex only",
    )
    require(
        "mtProxyTlsAutoRotateProfiles" in socket_cpp
        and "rotateMtProxyTlsProfileOnFailureIfNeeded" in socket_cpp
        and "currentEffectiveProxyTlsProfile" in socket_h,
        "native FakeTLS path must rotate effective JA4 profile on suspicious disconnect phases",
    )
    require(
        "client_hello_sent_no_server_hello" in socket_cpp
        and "server_hello_hmac_mismatch" in socket_cpp
        and "post_handshake_no_appdata" in socket_cpp
        and "tcp_connected_no_pong" in socket_cpp,
        "native rotation must be keyed by semantic diagnostic phases, not numeric errors",
    )
    require(
        "tcp_not_connected" in socket_cpp
        and "return false; // ClientHello was not sent, so JA4 did not cause this failure." in socket_cpp,
        "native rotation must not change JA4 for pre-TCP failures",
    )
    require(
        "getMtProxySoftMuxDownloadConnectionType" in connections
        and "getMtProxySoftMuxUploadConnectionType" in connections
        and "isMtProxyActiveForSoftMux" in connections,
        "ConnectionsManager must expose a soft mux connection-slot policy for MTProxy",
    )
    require(
        "getMtProxySoftMuxDownloadConnectionType(i)" in file_load
        and "getMtProxySoftMuxDownloadConnectionType(requestsCount)" in file_load,
        "FileLoadOperation must use the MTProxy soft mux policy for download slots",
    )
    require(
        "getMtProxySoftMuxUploadConnectionType(requestNumFinal)" in file_upload,
        "FileUploadOperation must use the MTProxy soft mux policy for upload slots",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        require(
            'name="MtProxyTlsProfileAutoRotate"' in source,
            f"{path.name} must define MtProxyTlsProfileAutoRotate",
        )

    print("MTProxy rotation and soft mux guard passed.")


if __name__ == "__main__":
    main()
