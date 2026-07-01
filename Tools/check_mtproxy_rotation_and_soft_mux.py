#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
PROXY_LIST = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java"
FILE_LOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java"
FILE_UPLOAD = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileUploadOperation.java"
SHARED_CONFIG = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
SOCKET_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
MACHINE_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocketStateMachine.h"
ADAPTIVE_CPP = ROOT / "TMessagesProj/jni/tgnet/MtProxyAdaptivePolicy.cpp"
HANDSHAKE_SCHEDULER_CPP = ROOT / "TMessagesProj/jni/tgnet/MtProxyHandshakeScheduler.cpp"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
WRAPPER_CPP = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
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
    shared_config = text(SHARED_CONFIG)
    socket_cpp = text(SOCKET_CPP)
    socket_h = text(SOCKET_H)
    adaptive_cpp = text(ADAPTIVE_CPP)
    handshake_scheduler_cpp = text(HANDSHAKE_SCHEDULER_CPP)
    socket_state = socket_h + "\n" + text(MACHINE_H) + "\n" + socket_cpp
    manager_cpp = text(MANAGER_CPP)
    manager_h = text(MANAGER_H)
    wrapper_cpp = text(WRAPPER_CPP)

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
        "tlsAutoRotateProfiles" in adaptive_cpp
        and "MtProxyAdaptivePolicy::rotateTlsProfileOnFailureIfNeeded" in adaptive_cpp
        and "MtProxyAdaptivePolicy::rotateTlsProfileOnFailureIfNeeded" in socket_cpp
        and "currentEffectiveProxyTlsProfile" in socket_state,
        "native FakeTLS path must rotate effective JA4 profile on suspicious disconnect phases",
    )
    require(
        "client_hello_sent_no_server_hello" in adaptive_cpp
        and "server_hello_hmac_mismatch" in adaptive_cpp
        and "post_handshake_no_appdata" in adaptive_cpp,
        "native rotation must be keyed by semantic diagnostic phases, not numeric errors",
    )
    rotation_start = adaptive_cpp.find("bool MtProxyAdaptivePolicy::failureNeedsRecipe")
    rotation_end = adaptive_cpp.find("int32_t MtProxyAdaptivePolicy::adaptiveTlsProfile", rotation_start)
    rotation_body = adaptive_cpp[rotation_start:rotation_end]
    require(
        "tcp_connected_no_pong" not in rotation_body
        and "dropped_after_appdata" not in rotation_body,
        "JA4 rotation must not react to plain-ping or already-after-appdata failures; those belong to endpoint/data lifecycle",
    )
    require(
        "tcp_not_connected" in adaptive_cpp
        and "return false; // ClientHello was not sent, so JA4 did not cause this failure." in adaptive_cpp,
        "native rotation must not change JA4 for pre-TCP failures",
    )
    require(
        "getMtProxySoftMuxDownloadConnectionType" in connections
        and "getMtProxySoftMuxUploadConnectionType" in connections
        and "isMtProxySoftMuxEnabled" in connections,
        "ConnectionsManager must expose a runtime soft mux connection-slot policy for MTProxy",
    )
    soft_mux_start = connections.find("private static boolean isMtProxySoftMuxEnabled()")
    soft_mux_end = connections.find("public static int getMtProxySoftMuxDownloadConnectionType", soft_mux_start)
    soft_mux_body = connections[soft_mux_start:soft_mux_end]
    require(
        'preferences.getString("proxy_secret", "")' in soft_mux_body
        and '"\\xee"' not in soft_mux_body
        and "MT_PROXY_TLS_PROFILE" not in soft_mux_body,
        "soft mux must apply to every MTProxy secret, including dd/legacy, not only ee FakeTLS",
    )
    require(
        "mtProxySoftMux" in shared_config
        and 'getBoolean("mtProxySoftMux", true)' in shared_config
        and 'putBoolean("mtProxySoftMux", mtProxySoftMux)' in shared_config,
        "SharedConfig must persist soft mux as an enabled-by-default runtime setting",
    )
    require(
        "mtProxySoftMuxRow" in proxy_list
        and "MtProxySoftMux" in proxy_list
        and "SharedConfig.mtProxySoftMux" in proxy_list,
        "proxy settings UI must expose a soft mux toggle",
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
    require(
        "mtProxyConnectionPatternMode" in shared_config
        and 'getInt("mtProxyConnectionPatternMode"' in shared_config
        and 'putInt("mtProxyConnectionPatternMode", mtProxyConnectionPatternMode)' in shared_config,
        "SharedConfig must persist connection-pattern modes",
    )
    require(
        'getBoolean("mtProxyHandshakeAdmission"' not in shared_config,
        "SharedConfig must not migrate the old admission-controller boolean",
    )
    require(
        "mtProxyConnectionPatternRow" in proxy_list
        and "MtProxyConnectionPattern" in proxy_list
        and "SharedConfig.mtProxyConnectionPatternMode" in proxy_list
        and "MT_PROXY_CONNECTION_PATTERN_OPTIONS" in proxy_list,
        "proxy settings UI must expose connection-pattern modes",
    )
    require(
        "resolveMtProxyConnectionPatternMode()" in connections
        and "mtProxyConnectionPatternMode" in connections
        and "MtProxyOptions.resolve(proxyAddress, proxyPort, proxySecret)" in connections,
        "Java must pass the runtime connection-pattern mode through MtProxyOptions",
    )
    require(
        'native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;ILjava/lang/String;)V"' in wrapper_cpp
        and 'native_checkProxy", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;Lorg/telegram/tgnet/RequestTimeDelegate;)J"' in wrapper_cpp,
        "JNI signatures must carry the admission-controller mode through MtProxyOptions",
    )
    require(
        "MtProxyOptions proxyMtProxyOptions" in manager_h
        and "optionsChanged" in manager_cpp
        and "proxyMtProxyOptions = normalizedOptions" in manager_cpp,
        "native ConnectionsManager must store connection-pattern runtime state in MtProxyOptions and reconnect when it changes",
    )
    require(
        "MT_PROXY_HANDSHAKE_ADMISSION_ENABLED" not in socket_cpp
        and "mtProxyHandshakeSchedulerUsesAdmission" in socket_cpp
        and "mtProxyHandshakeSchedulerUsesAdmission(int32_t mode)" in handshake_scheduler_cpp
        and "admission_disabled" in socket_cpp,
        "ConnectionSocket must use runtime connection-pattern state instead of a compile-time disabled flag",
    )
    require(
        "releaseRequest.suppressQueuedGrant = suppressQueuedGrant" in socket_cpp
        and "mtProxyHandshakeSchedulerRelease(releaseRequest)" in socket_cpp
        and "if (!request.suppressQueuedGrant && mtProxyHandshakeSchedulerUsesAdmission(mode))" in handshake_scheduler_cpp
        and "mtProxyTakeNextQueuedRequestGlobalLocked(request.now, mode, decision.nextRequest)" in handshake_scheduler_cpp,
        "ConnectionSocket must not grant queued admission requests after the runtime gate is disabled",
    )
    require(
        "MtProxyRequestClass" in handshake_scheduler_cpp
        and "request_class=%s" in socket_cpp
        and "mtProxyHandshakeHeavyBlockedBeforeUsable" in handshake_scheduler_cpp
        and "MT_PROXY_STARTUP_GLOBAL_HANDSHAKES_STRICT" in handshake_scheduler_cpp,
        "runtime connection-pattern scheduler must be request-class aware without bypassing soft-mux/admission gates",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        require(
            'name="MtProxyTlsProfileAutoRotate"' in source,
            f"{path.name} must define MtProxyTlsProfileAutoRotate",
        )
        require(
            'name="MtProxySoftMux"' in source
            and 'name="MtProxySoftMuxInfo"' in source
            and 'name="MtProxyConnectionPattern"' in source
            and 'name="MtProxyConnectionPatternInfo"' in source,
            f"{path.name} must define soft mux and connection-pattern strings",
        )

    print("MTProxy rotation and soft mux guard passed.")


if __name__ == "__main__":
    main()
