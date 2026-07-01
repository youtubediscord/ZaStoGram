#!/usr/bin/env python3
from pathlib import Path
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
SHAPER_H = ROOT / "TMessagesProj/jni/tgnet/MtProxyDataPathShaper.h"
SHAPER_CPP = ROOT / "TMessagesProj/jni/tgnet/MtProxyDataPathShaper.cpp"
CMAKE = ROOT / "TMessagesProj/jni/CMakeLists.txt"
PROXY_CHECK = ROOT / "TMessagesProj/jni/tgnet/ProxyCheckInfo.h"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def text(path: Path) -> str:
    if not path.exists():
        return ""
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
    shaper_h = text(SHAPER_H)
    shaper_cpp = text(SHAPER_CPP)
    cmake = text(CMAKE)
    socket_state = socket_h + "\n" + text(MACHINE_H) + "\n" + socket_cpp
    proxy_check = text(PROXY_CHECK)

    require(
        "mtProxyRecordSizingMode" in shared_config
        and 'getInt("mtProxyRecordSizingMode", 0)' in shared_config
        and 'putInt("mtProxyRecordSizingMode", mtProxyRecordSizingMode)' in shared_config,
        "SharedConfig must persist TLS record sizing mode as a runtime setting",
    )
    require(
        "mtProxyTimingMode" in shared_config
        and 'getInt("mtProxyTimingMode", 0)' in shared_config
        and 'putInt("mtProxyTimingMode", mtProxyTimingMode)' in shared_config,
        "SharedConfig must persist inter-packet timing mode as a runtime setting",
    )
    require(
        "MT_PROXY_RECORD_SIZING_OFF" in connections
        and "MT_PROXY_RECORD_SIZING_CONSERVATIVE" in connections
        and "MT_PROXY_RECORD_SIZING_VARIED" in connections
        and "resolveMtProxyRecordSizingMode()" in connections,
        "Java must expose record sizing mode constants and resolver",
    )
    require(
        "MT_PROXY_TIMING_OFF" in connections
        and "MT_PROXY_TIMING_GENTLE" in connections
        and "MT_PROXY_TIMING_BALANCED" in connections
        and "resolveMtProxyTimingMode()" in connections,
        "Java must expose timing mode constants and resolver",
    )
    require(
        "mtProxyRecordSizingRow" in proxy_list
        and "getMtProxyRecordSizingLabels" in proxy_list
        and "SharedConfig.mtProxyRecordSizingMode" in proxy_list,
        "proxy settings UI must expose selectable TLS record sizing modes",
    )
    require(
        "mtProxyTimingRow" in proxy_list
        and "getMtProxyTimingLabels" in proxy_list
        and "SharedConfig.mtProxyTimingMode" in proxy_list,
        "proxy settings UI must expose selectable timing modes",
    )
    require(
        'native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;ILjava/lang/String;)V"' in wrapper
        and 'native_checkProxy", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/MtProxyOptions;Lorg/telegram/tgnet/RequestTimeDelegate;)J"' in wrapper,
        "JNI signatures must carry profile, fragmentation, admission, record sizing, timing, and startup-cover via MtProxyOptions",
    )
    require(
        "MtProxyOptions proxyMtProxyOptions" in manager_h
        and "optionsChanged" in manager_cpp
        and "proxyMtProxyOptions = normalizedOptions" in manager_cpp,
        "native ConnectionsManager must store data-path modes in MtProxyOptions and reconnect when they change",
    )
    require(
        "MtProxyOptions mtProxyOptions" in proxy_check,
        "proxy checks must carry MtProxyOptions for same-path testing",
    )
    require(
        "currentRecordSizingMode" in socket_state
        and "currentTimingMode" in socket_state
        and "mtproxyTlsFrameCompletedCount" in socket_state
        and "nextMtProxyTlsRecordPayloadSize" in shaper_cpp
        and "scheduleMtProxyDataTimingIfNeeded" in socket_cpp,
        "MtProxyDataPathShaper must own record sizing policy while ConnectionSocket applies timing waits in the FakeTLS data path",
    )
    require(
        "remaining > sizingDecision.payloadSize" in socket_cpp
        and "mtproxy_data record_sizing" in socket_cpp
        and "mtproxy_data timing_delay" in socket_cpp,
        "data-path layers must be logged and must not replace the pending TLS write queue",
    )
    require(
        "MtProxyDataPathShaper.cpp" in cmake
        and "MtProxyDataPathShaper.h" in socket_cpp,
        "native build and ConnectionSocket must use the MtProxyDataPathShaper module",
    )
    require(
        "struct MtProxyRecordSizingInput" in shaper_h
        and "struct MtProxyStartupCoverPolicy" in shaper_h
        and "struct MtProxyDataTimingDecision" in shaper_h
        and "mtProxyEffectiveRecordSizingMode" in shaper_cpp
        and "mtProxyEffectiveTimingMode" in shaper_cpp
        and "mtProxyStartupCoverPolicy" in shaper_cpp
        and "mtProxyDataTimingDecision" in shaper_cpp
        and "mtProxyDataAwareIptDelayMs" in shaper_cpp,
        "MtProxyDataPathShaper must own record sizing, timing, and startup-cover decisions",
    )
    require(
        "uint32_t ConnectionSocket::nextMtProxyTlsRecordPayloadSize" not in socket_cpp
        and "static uint32_t mtProxyDataAwareIptDelayMs" not in socket_cpp
        and "MT_PROXY_STARTUP_COVER_SOFT_WINDOW_MS" not in socket_cpp
        and "MT_PROXY_STARTUP_COVER_STRICT_WINDOW_MS" not in socket_cpp
        and "currentStartupCoverMode == MT_PROXY_STARTUP_COVER_STRICT ? MT_PROXY_RECORD_SIZING_VARIED" not in socket_cpp
        and "currentStartupCoverMode == MT_PROXY_STARTUP_COVER_STRICT ? MT_PROXY_TIMING_BALANCED" not in socket_cpp,
        "ConnectionSocket must not regrow data-path shaping policy",
    )
    send_start = socket_cpp.find("bool ConnectionSocket::sendPendingTlsFrame()")
    send_end = socket_cpp.find("void ConnectionSocket::openConnection", send_start)
    schedule_start = socket_cpp.find("bool ConnectionSocket::scheduleMtProxyDataTimingIfNeeded()")
    schedule_end = socket_cpp.find("void ConnectionSocket::startMtProxyStartupCover", schedule_start)
    require(send_start != -1 and send_end != -1, "sendPendingTlsFrame body must be present")
    require(schedule_start != -1 and schedule_end != -1, "scheduleMtProxyDataTimingIfNeeded body must be present")
    send_body = socket_cpp[send_start:send_end]
    schedule_body = socket_cpp[schedule_start:schedule_end]
    discard_pos = send_body.find("outgoingByteStream->discard(pendingTlsPayloadSize);")
    complete_count_pos = send_body.find("mtproxyTlsFrameCompletedCount++")
    complete_log_pos = send_body.find("mtproxy_data tls_frame_complete")
    clear_pos = send_body.find("clearPendingTlsFrame();")
    timing_pos = send_body.find("nextTlsFrameWriteTime")
    require(
        discard_pos != -1 and clear_pos != -1 and discard_pos < clear_pos,
        "FakeTLS data path must discard payload only after the full TLS frame was sent and before clearing the pending frame",
    )
    require(
        discard_pos < complete_count_pos < clear_pos
        and discard_pos < complete_log_pos < clear_pos,
        "FakeTLS record-boundary diagnostics must be emitted only after payload discard and before clearing the completed TLS frame",
    )
    require(
        "tls_frames_completed=%u" in socket_cpp,
        "mtproxy_disconnect must include the completed FakeTLS frame count so long-session data-path drops remain diagnosable",
    )
    require(
        clear_pos < timing_pos
        and "MtProxyDataTimingDecision timingDecision = mtProxyDataTimingDecision" in send_body
        and "timingDecision.shouldDelay" in send_body,
        "data-aware IPT must be scheduled only after a complete TLS frame, never while a partial TLS frame is pending",
    )
    require(
        "mtProxyDataTimingWaitDecision" in schedule_body
        and "pendingTlsFrame != nullptr" in schedule_body,
        "data-aware IPT wait must be skipped while a TLS frame is pending or when no delay was scheduled",
    )
    for path in (STRINGS, STRINGS_RU):
        source = text(path)
        for key in (
            "MtProxyRecordSizing",
            "MtProxyRecordSizingOff",
            "MtProxyRecordSizingConservative",
            "MtProxyRecordSizingVaried",
            "MtProxyTiming",
            "MtProxyTimingOff",
            "MtProxyTimingGentle",
            "MtProxyTimingBalanced",
        ):
            require(f'name="{key}"' in source, f"{path.name} must define {key}")

    print("MTProxy data-layer guard passed.")


if __name__ == "__main__":
    main()
