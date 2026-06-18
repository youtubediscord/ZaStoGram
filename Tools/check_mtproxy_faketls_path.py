#!/usr/bin/env python3
"""Static guard for the active MTProxy FakeTLS transport path.

The working reference is tsrman/tg commit 9fe18931 for the risky transport
parts: whole ClientHello send and the original fixed TLS record cap for wrapped
data. ZaStoGram adds a sticky FakeTLS profile selector, a nonblocking
endpoint-level startup scheduler, startup diagnostics, and a TLS write queue so
MTProto payload bytes are not discarded until the full TLS record has been sent.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
HDR = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
CONNECTION_CPP = ROOT / "TMessagesProj/jni/tgnet/Connection.cpp"
PROXY_CHECK_HDR = ROOT / "TMessagesProj/jni/tgnet/ProxyCheckInfo.h"
CM_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
CM_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
CM_HDR = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
WRAPPER = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"


def main() -> int:
    cpp = CPP.read_text(encoding="utf-8")
    header = HDR.read_text(encoding="utf-8")
    connection_cpp = CONNECTION_CPP.read_text(encoding="utf-8")
    proxy_check_header = PROXY_CHECK_HDR.read_text(encoding="utf-8")
    java = CM_JAVA.read_text(encoding="utf-8")
    manager_cpp = CM_CPP.read_text(encoding="utf-8")
    manager_header = CM_HDR.read_text(encoding="utf-8")
    wrapper = WRAPPER.read_text(encoding="utf-8")
    combined = cpp + "\n" + header
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require("MT_PROXY_TLS_PROFILE_AUTO" in java, "Java must define the auto MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_FIREFOX" in java, "Java must define the Firefox MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_ANDROID_CHROME" in java, "Java must define the Android Chrome MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_YANDEX" in java, "Java must define the Yandex MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID" in java, "Java must define the Firefox Android MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP" in java, "Java must define the Android OkHttp MTProxy TLS profile")
    require("MT_PROXY_TLS_PROFILE_RANDOM_COUNT = 5" in java, "sticky MTProxy auto pool must include five profiles")
    require(
        "resolveMtProxyTlsProfile" in java
        and "MT_PROXY_TLS_PROFILE_SALT" in java
        and "stableMtProxyTlsHash" in java,
        "Java must choose a sticky profile from endpoint, secret, and local salt",
    )
    require(
        "native_setProxySettings(currentAccount, proxyAddress, proxyPort, proxyUsername, proxyPassword, proxySecret, mtProxyTlsProfile)" in java
        and "native_setProxySettings(a, address, port, username, password, secret, mtProxyTlsProfile)" in java,
        "Java must pass the selected MTProxy TLS profile into native proxy settings",
    )
    require(
        "native_checkProxy(currentAccount, address, port, username, password, secret, mtProxyTlsProfile, requestTimeDelegate)" in java,
        "Java proxy checks must use the same selected MTProxy TLS profile as real connections",
    )
    require(
        "native_setProxySettings(int currentAccount, String address, int port, String username, String password, String secret, int mtProxyTlsProfile)" in java,
        "Java native_setProxySettings declaration must include the MTProxy TLS profile",
    )
    require(
        'native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V"' in wrapper,
        "JNI native_setProxySettings signature must include the MTProxy TLS profile int",
    )
    require(
        'native_checkProxy", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILorg/telegram/tgnet/RequestTimeDelegate;)J"' in wrapper,
        "JNI native_checkProxy signature must include the MTProxy TLS profile int",
    )
    require(
        "setProxySettings(std::string address, uint16_t port, std::string username, std::string password, std::string secret, int32_t mtProxyTlsProfile)" in manager_header
        and "ConnectionsManager::setProxySettings(std::string address, uint16_t port, std::string username, std::string password, std::string secret, int32_t mtProxyTlsProfile)" in manager_cpp,
        "ConnectionsManager::setProxySettings must store the MTProxy TLS profile",
    )
    require(
        "int32_t proxyTlsProfile" in manager_header
        and "profileChanged" in manager_cpp
        and "proxyTlsProfile = normalizeMtProxyTlsProfile(mtProxyTlsProfile)" in manager_cpp,
        "ConnectionsManager must keep profile state and reconnect on profile changes",
    )
    require(
        "mtProxyTlsProfile >= 1 && mtProxyTlsProfile <= 5" in manager_cpp,
        "Native ConnectionsManager profile normalization must accept the full sticky pool",
    )
    require(
        "int32_t mtProxyTlsProfile" in proxy_check_header
        and "setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, int32_t mtProxyTlsProfile)" in header
        and "connection->setOverrideProxy(proxyCheckInfo->address, proxyCheckInfo->port, proxyCheckInfo->username, proxyCheckInfo->password, proxyCheckInfo->secret, proxyCheckInfo->mtProxyTlsProfile)" in manager_cpp,
        "Proxy check override connections must carry the selected MTProxy TLS profile",
    )
    require(
        "getFirefoxDefault" in cpp
        and "getAndroidChromeDefault" in cpp
        and "getYandexDefault" in cpp
        and "getFirefoxAndroidDefault" in cpp
        and "getAndroidOkHttpDefault" in cpp
        and "selectMtProxyTlsHello" in cpp,
        "FakeTLS must expose Firefox, Android Chrome, Yandex, Firefox Android, and Android OkHttp ClientHello profiles through a selector",
    )
    require(
        "TlsHello hello = selectMtProxyTlsHello(" in cpp,
        "FakeTLS handshake must instantiate ClientHello through the sticky profile selector",
    )
    require(
        not re.search(r"\bTlsHello\s+TlsHello::pickProfile\s*\(", cpp),
        "FakeTLS profile wrapper must stay out of the active transport path",
    )
    require("randomizeGrease" not in cpp and "randomizeGrease" not in header, "per-connection GREASE rewrite must stay disabled")
    require(
        "grease[i - 1]" in cpp and "grease[i + 1]" not in cpp,
        "GREASE initialization must not read past the fixed GREASE array",
    )
    require(
        "validateServerCompatibleHello" in cpp
        and "cipherSuitesOffset = 76" in cpp
        and "first non-GREASE cipher" in cpp,
        "Each selected ClientHello must pass server-compatible guard checks",
    )
    require(
        "mtproxy_startup profile" in cpp,
        "MTProxy diagnostics must log selected FakeTLS profile",
    )
    require(
        "send(socketFd, tempBuffer->bytes, size, 0)" in cpp,
        "ClientHello must be sent whole like the working tsrman path",
    )
    require(
        "remaining > 2878" in cpp,
        "wrapped data path must keep the original fixed TLS record cap",
    )
    require(
        "nextTlsRecordSize" not in combined
        and "tlsRecordRemaining" not in combined
        and "drs" not in combined.lower(),
        "dynamic record sizing must stay removed from the transport path",
    )
    require(
        "nanosleep(&ts, nullptr);" not in cpp,
        "proxy startup scheduling must not block the network thread",
    )
    require(
        "scheduleProxyHandshakeAdmissionIfNeeded" in combined
        and "cancelProxyHandshakeAdmission" in combined
        and "Timer *proxyHandshakeAdmissionTimer" in header
        and '#include "Timer.h"' in cpp,
        "proxy startup scheduling must use a cancellable nonblocking Timer",
    )
    require(
        "MtProxyHandshakeEndpointState" in cpp
        and "proxyHandshakeSchedulerMutex" in cpp
        and "activeHandshakes" in cpp
        and "cooldownUntil" in cpp
        and "queuedRequests" in cpp,
        "FakeTLS startup must use an endpoint-level admission controller, not a single global jitter timestamp",
    )
    require(
        "lastProxyConnectTime" not in cpp
        and "proxyJitterMutex" not in cpp,
        "old global jitter-only scheduler must stay out of the active FakeTLS path",
    )
    require(
        "setMtProxyHandshakePriority" in combined
        and "mtProxyHandshakePriorityForConnectionType" in connection_cpp
        and "ConnectionTypeGenericMedia" in connection_cpp
        and "ConnectionTypeProxy" in connection_cpp,
        "FakeTLS admission must receive MTProto connection priority before opening the socket",
    )
    require(
        "MT_PROXY_HANDSHAKE_PRIORITY_BYPASS" in cpp
        and "proxyHandshakeAdmissionPriority == MT_PROXY_HANDSHAKE_PRIORITY_BYPASS" in cpp
        and "case ConnectionTypeProxy:" in connection_cpp
        and "return -1;" in connection_cpp,
        "Proxy checks must bypass hard FakeTLS admission queue to avoid false dead-proxy results",
    )
    require(
        "releaseProxyHandshakeAdmission(true" in cpp
        and "server_hello_hmac_ok" in cpp,
        "FakeTLS admission slot must be released as soon as server_hello_hmac_ok is reached",
    )
    require(
        "releaseProxyHandshakeAdmission(false" in cpp
        and "closeSocket" in cpp,
        "FakeTLS admission slot must be released on disconnect/error/timeout",
    )
    require(
        "proxyHandshakeClientHelloSentTime" in combined
        and "markProxyHandshakeClientHelloSent" in combined
        and "freeze" in cpp.lower(),
        "FakeTLS admission must record ClientHello time and apply freeze-aware cooldowns",
    )
    require(
        "shouldApplyFreezeCooldown" in cpp
        and "clientHelloElapsed >= MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS" in cpp
        and "mtProxyApplyFreezeCooldown(state, now)" in cpp,
        "FakeTLS cooldown must be applied only to real freezes, not every post-ClientHello close",
    )
    require(
        "pacingDeferred" not in combined,
        "old deferred pacing path must stay out of MTProxy connect",
    )
    require(
        "mtproxy_startup connect_start" in cpp
        and "mtproxy_startup socket_connected" in cpp
        and "mtproxy_startup client_hello_sent" in cpp
        and "mtproxy_startup server_hello_hmac_ok" in cpp
        and "mtproxy_startup on_connected" in cpp
        and "mtproxy_disconnect" in cpp,
        "MTProxy startup diagnostics must cover connect, TLS handshake, connected, and disconnect",
    )
    require(
        "pendingTlsFrame" in combined
        and "sendPendingTlsFrame" in combined
        and "clearPendingTlsFrame" in combined,
        "TLS writes must keep a pending frame for partial-send handling",
    )

    if errors:
        print("MTProxy FakeTLS path check failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("MTProxy FakeTLS path check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
