#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
NATIVE = ROOT / "TMessagesProj/jni/tgnet"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"
RUNTIME_LOG_VERIFIER = ROOT / "Tools/verify_mtproxy_runtime_logs.py"


LIVE_PHASES_HELD_BY_USABLE_SUCCESS = (
    ("dns_cache_hit", "DNS_CACHE_HIT"),
    ("dns_cache_store", "DNS_CACHE_STORE"),
    ("dns_coalesce_wait", "DNS_COALESCE_WAIT"),
    ("connect_start", "CONNECT_START"),
    ("socket_connect_start", "SOCKET_CONNECT_START"),
    ("tcp_connect_gate", "TCP_CONNECT_GATE"),
    ("socket_connected", "SOCKET_CONNECTED"),
    ("client_hello_sent", "CLIENT_HELLO_SENT"),
    ("server_hello_hmac_ok", "SERVER_HELLO_HMAC_OK"),
    ("on_connected", "ON_CONNECTED"),
    ("first_tls_app_sent", "FIRST_TLS_APP_SENT"),
    ("admission_queue", "ADMISSION_QUEUE"),
    ("endpoint_cooldown", "ENDPOINT_COOLDOWN"),
    ("host_resolve_start", "HOST_RESOLVE_START"),
)

USABLE_SUCCESS_PHASES = (
    ("first_tls_app_recv", "FIRST_TLS_APP_RECV"),
    ("first_mtproxy_packet_recv", "FIRST_MTPROXY_PACKET_RECV"),
)

PUNITIVE_FAILURE_PHASES = (
    ("tcp_not_connected", "TCP_NOT_CONNECTED"),
    ("host_resolve_failed", "HOST_RESOLVE_FAILED"),
    ("host_resolve_timeout", "HOST_RESOLVE_TIMEOUT"),
    ("client_hello_sent_no_server_hello", "CLIENT_HELLO_SENT_NO_SERVER_HELLO"),
    ("server_hello_hmac_mismatch", "SERVER_HELLO_HMAC_MISMATCH"),
    ("mtproxy_packet_sent_no_response", "MTPROXY_PACKET_SENT_NO_RESPONSE"),
    ("post_handshake_no_appdata", "POST_HANDSHAKE_NO_APPDATA"),
    ("dropped_early_after_appdata", "DROPPED_EARLY_AFTER_APPDATA"),
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    brace = text.find("{", start)
    if brace == -1:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def run_analyzer_shadow_check(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp)
        markers = session / "mtproxy_markers.txt"
        markers.write_text(
            "\n".join(
                [
                    "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) connecting via proxy sberbank.dns.army:45631 secret[34] secret_kind=ee",
                    "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup connect_start profile=firefox_android address=sberbank.dns.army port=45631",
                    "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup socket_connect_start",
                    "logcat.txt:4: 06-25 20:31:30.030 connection(0x1) mtproxy_startup socket_connected",
                    "logcat.txt:5: 06-25 20:31:30.040 connection(0x1) mtproxy_startup client_hello_sent bytes=2206",
                    "logcat.txt:6: 06-25 20:31:30.060 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
                    "logcat.txt:7: 06-25 20:31:30.070 connection(0x1) mtproxy_startup on_connected tls=1",
                    "logcat.txt:8: 06-25 20:31:30.080 connection(0x1) mtproxy_startup first_tls_app_sent payload=244 frame=249",
                    "logcat.txt:9: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
                    "logcat.txt:10: 06-25 20:31:30.100 proxy_control decision=visible_usable_success source=native_stage account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    "logcat.txt:11: 06-25 20:31:30.110 proxy_control decision=held_connect_start_by_usable_success source=connect_start phase=connect_start endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army held_by=first_tls_app_recv",
                    "logcat.txt:12: 06-25 20:31:30.120 proxy_control decision=held_live_by_usable_success source=native_stage account=0 phase=tcp_connect_gate endpoint=sberbank.dns.army:45631 held_by=first_tls_app_recv",
                    "logcat.txt:13: 06-25 20:31:30.200 connection(0x2) connecting via proxy sberbank.dns.army:45631 secret[34] secret_kind=ee",
                    "logcat.txt:14: 06-25 20:31:30.210 connection(0x2) mtproxy_startup endpoint_failure_shadowed_by_success key=sberbank.dns.army:45631 phase=tcp_not_connected reason=closeSocket hold_ms=44900",
                    "logcat.txt:15: 06-25 20:31:30.220 proxy_control decision=held_by_usable_success source=native_stage account=0 phase=tcp_not_connected endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army held_by=first_tls_app_recv",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(markers), "--out-dir", str(session)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(result.returncode == 0, result.stderr.strip() or result.stdout, failures)
        require("ok: 1" in result.stdout, "analyzer must keep the proven usable attempt as ok", failures)
        require("tcp_not_connected: 1" not in result.stdout, "shadowed sibling failure must not count as tcp_not_connected", failures)
        require("endpoint_failure_shadowed_by_success" in result.stdout, "analyzer must preserve the shadow marker", failures)
        require("held_by_usable_success" in result.stdout, "analyzer must preserve Java usable-success hold decisions", failures)
        require("held_connect_start_by_usable_success" in result.stdout, "analyzer must preserve Java connect-start hold decisions", failures)
        require("held_live_by_usable_success" in result.stdout, "analyzer must preserve Java live-stage hold decisions", failures)


def runtime_log_lines(proxy_control_tail: str) -> str:
    return (
        "\n".join(
            [
                "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
                "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
                "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
                "logcat.txt:4: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
                "logcat.txt:5: 06-25 20:31:30.100 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=sberbank.dns.army:45631 key=sberbank.dns.army:45631:ee:sberbank.dns.army reason=first_tls_app_recv",
                "logcat.txt:6: 06-25 20:31:30.110 proxy_control decision=visible_usable_success source=native_stage account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                proxy_control_tail,
            ]
        )
        + "\n"
    )


def run_runtime_log_visible_hold_check(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp)
        bad = session / "bad_markers.txt"
        good = session / "good_markers.txt"
        bad.write_text(
            runtime_log_lines(
                "logcat.txt:7: 06-25 20:31:31.110 proxy_control decision=visible_only source=native_stage account=0 phase=tcp_connect_gate endpoint=sberbank.dns.army:45631"
            ),
            encoding="utf-8",
        )
        good.write_text(
            runtime_log_lines(
                "logcat.txt:7: 06-25 20:31:31.110 proxy_control decision=held_live_by_usable_success source=native_stage account=0 phase=tcp_connect_gate endpoint=sberbank.dns.army:45631 held_by=first_tls_app_recv"
            ),
            encoding="utf-8",
        )
        bad_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(bad)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            bad_result.returncode != 0
            and "visible usable success overwritten by live visible_only" in bad_result.stderr,
            "runtime log verifier must fail when a fresh usable success is overwritten by a live visible_only phase within 45s",
            failures,
        )
        good_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(good)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            good_result.returncode == 0,
            good_result.stderr.strip() or "runtime log verifier must allow held_live_by_usable_success after visible usable success",
            failures,
        )


def main() -> int:
    failures: list[str] = []
    store = read(MESSENGER / "ProxyRuntimeStateStore.java")
    health = read(MESSENGER / "ProxyHealthStore.java")
    rotation = read(MESSENGER / "ProxyRotationController.java")
    engine = read(MESSENGER / "ProxyRotationEngine.java")
    policy_h = read(NATIVE / "MtProxyEndpointPolicy.h")
    policy_cpp = read(NATIVE / "MtProxyEndpointPolicy.cpp")
    socket = read(NATIVE / "ConnectionSocket.cpp")
    analyzer = read(ANALYZER)
    all_checks = read(ROOT / "Tools/check_mtproxy_all.py")

    require("public static boolean hasFreshUsableSuccess" in store, "runtime store must expose fresh usable-success state", failures)
    require("public static long usableSuccessRemainingMs" in store, "runtime store must expose remaining usable-success hold", failures)
    require("static long usableSuccessRemainingMs" in health, "health store must expose usable-success remaining time", failures)

    native_stage = method_body(store, "public static Decision onNativeStage")
    helper = method_body(store, "private static boolean shouldHoldLivePhaseByUsableSuccess")
    live_hold_idx = native_stage.find("decision=held_live_by_usable_success")
    connected_hold_idx = native_stage.find("decision=held_live_by_current_proxy_usable")
    visible_write_idx = native_stage.find("if (selectedAccountStage && ProxyPhasePolicy.canOverwriteVisible(event.phase))")
    helper_call_idx = native_stage.find("shouldHoldLivePhaseByUsableSuccess(currentProxy, event)")
    require(
        helper
        and "String phase = ProxyCheckDiagnostics.normalize(event.phase)" in helper
        and "ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, event.timestamp)" in helper
        and "ProxyPhasePolicy.isLivePhase(phase)" in helper
        and "ProxyPhasePolicy.isProxyUsableSuccessPhase(phase)" in helper,
        "runtime store must keep usable-success live telemetry hold in a dedicated shouldHoldLivePhaseByUsableSuccess helper",
        failures,
    )
    require(
        live_hold_idx >= 0
        and visible_write_idx >= 0
        and helper_call_idx >= 0
        and helper_call_idx < visible_write_idx
        and live_hold_idx < visible_write_idx
        and 'return new Decision("held_live_by_usable_success"' in native_stage,
        "fresh usable success must hold later live pre-TCP native stages before they can overwrite visible state",
        failures,
    )
    phase_policy = read(MESSENGER / "ProxyPhasePolicy.java")
    for phase, constant in LIVE_PHASES_HELD_BY_USABLE_SUCCESS:
        require(
            f"ProxyCheckDiagnostics.{constant}" in phase_policy
            and f"case ProxyCheckDiagnostics.{constant}:" in phase_policy
            and f"MtProxyPhase(\"{phase}\", PHASE_LIVE" in read(ROOT / "Tools/mtproxy_phase_contract.py"),
            f"{phase} must be classified as live telemetry held by fresh usable success",
            failures,
        )
    for phase, constant in USABLE_SUCCESS_PHASES:
        require(
            f"case ProxyCheckDiagnostics.{constant}:" in phase_policy
            and f"MtProxyPhase(\"{phase}\", PHASE_SUCCESS" in read(ROOT / "Tools/mtproxy_phase_contract.py"),
            f"{phase} must be classified as usable success rather than live telemetry",
            failures,
        )
    for phase, constant in PUNITIVE_FAILURE_PHASES:
        require(
            f"case ProxyCheckDiagnostics.{constant}:" in phase_policy
            and f"MtProxyPhase(\"{phase}\", PHASE_FAILURE" in read(ROOT / "Tools/mtproxy_phase_contract.py")
            and f"MtProxyPhase(\"{phase}\", PHASE_FAILURE" in read(ROOT / "Tools/mtproxy_phase_contract.py").split("MtProxyPhase(\"dropped_after_appdata\"")[0],
            f"{phase} must remain a punitive failure handled through backoff/rotation policy, not visible live telemetry",
            failures,
        )
    require(
        "public static boolean isCurrentProxyUsable" in store
        and connected_hold_idx >= 0
        and connected_hold_idx < visible_write_idx
        and "isCurrentProxyUsable(currentProxy, event.timestamp)" in native_stage
        and 'return new Decision("held_live_by_current_proxy_usable"' in native_stage,
        "selected-account connected/updating current proxy must hold later live socket telemetry before visible writes",
        failures,
    )
    mark_start = method_body(store, "public static void markConnectionStarting")
    connect_start_hold_idx = mark_start.find("decision=held_connect_start_by_usable_success")
    clear_hold_idx = mark_start.find("ProxyHealthStore.clearUsableSuccessHold(proxyInfo)")
    mark_visible_idx = mark_start.find("ProxyStatusMirror.markConnectionStarting(proxyInfo, now)")
    require(
        connect_start_hold_idx >= 0
        and clear_hold_idx >= 0
        and mark_visible_idx >= 0
        and connect_start_hold_idx < clear_hold_idx
        and connect_start_hold_idx < mark_visible_idx
        and "ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)" in mark_start
        and "return;" in mark_start[connect_start_hold_idx:clear_hold_idx],
        "Java connect_start must be held by fresh usable success before clearing the hold or overwriting visible state",
        failures,
    )
    require(
        "isCurrentProxyUsable(proxyInfo, now)" in mark_start
        and connect_start_hold_idx < mark_visible_idx,
        "Java connect_start must also be held while the selected account is already connected/updating through the current proxy",
        failures,
    )

    status_text = method_body(read(MESSENGER / "ProxyCheckDiagnostics.java"), "public static String statusText")
    header_text = method_body(read(MESSENGER / "ProxyCheckDiagnostics.java"), "public static String headerStatusText")
    color_key = method_body(read(MESSENGER / "ProxyCheckDiagnostics.java"), "public static int statusColorKey")
    connected_check = "currentConnectionState == ConnectionsManager.ConnectionStateConnected || currentConnectionState == ConnectionsManager.ConnectionStateUpdating"
    require(
        status_text.find(connected_check) != -1
        and status_text.find("hasFreshLivePhase(proxyInfo)") != -1
        and status_text.find(connected_check) < status_text.find("hasFreshLivePhase(proxyInfo)"),
        "connected current-proxy status text must outrank unresolved live socket phases",
        failures,
    )
    require(
        header_text.find(connected_check) != -1
        and header_text.find("hasFreshLivePhase(proxyInfo)") != -1
        and header_text.find(connected_check) < header_text.find("hasFreshLivePhase(proxyInfo)"),
        "connected current-proxy header text must outrank unresolved live socket phases",
        failures,
    )
    require(
        color_key.find(connected_check) != -1
        and color_key.find("hasFreshLivePhase(proxyInfo)") != -1
        and color_key.find(connected_check) < color_key.find("hasFreshLivePhase(proxyInfo)"),
        "connected current-proxy color must outrank unresolved live socket phases",
        failures,
    )

    rotation_stage = rotation[rotation.find("NotificationCenter.proxyConnectionStageChanged"):]
    require(
        "ProxyRuntimeStateStore.isCurrentProxyUsable(SharedConfig.currentProxy)" in rotation_stage
        and "cancelScheduledSwitch(\"usable_success\")" in rotation_stage
        and "cancel usable_success" in rotation_stage,
        "rotation controller must cancel pending switches on current-proxy usable success",
        failures,
    )

    complete_attempt = method_body(engine, "SwitchDecision completeScheduledAttempt")
    require(
        "ProxyRuntimeStateStore.isCurrentProxyUsable(currentProxy)" in complete_attempt
        and "SwitchDecision.held" in complete_attempt
        and complete_attempt.find("isCurrentProxyUsable") < complete_attempt.find("markEndpointFailure"),
        "rotation engine must hold scheduled attempts before marking connecting timeout failure",
        failures,
    )
    should_schedule = method_body(store, "public static boolean shouldScheduleFallback")
    require(
        "isCurrentProxyUsable(currentProxy" in should_schedule,
        "fallback scheduling must treat fresh usable success or connected/updating current proxy as usable",
        failures,
    )

    require("MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS" in policy_cpp, "native endpoint policy must define a usable-success hold window", failures)
    require("shadowedByUsableSuccess" in policy_h, "FailureResult must report shadowed usable-success failures", failures)
    require("failureCanBeShadowedBySuccess" in policy_cpp, "native policy must restrict which failures can be shadowed", failures)
    require('"dropped_early_after_appdata"' in policy_cpp and '"dropped_after_appdata"' in policy_cpp, "native policy must explicitly leave post-data drops unshadowed", failures)
    record_failure = method_body(policy_cpp, "MtProxyEndpointPolicy::FailureResult MtProxyEndpointPolicy::recordFailure")
    require(
        "usableSuccessRemainingMsLocked" in record_failure
        and "result.shadowedByUsableSuccess = true" in record_failure
        and "return result" in record_failure,
        "recordFailure must return a shadowed result without increasing cooldown counters",
        failures,
    )
    failure_body = method_body(socket, "void ConnectionSocket::recordMtProxyEndpointFailure")
    require(
        "endpoint_failure_shadowed_by_success" in failure_body
        and "shadowedByUsableSuccess" in failure_body
        and "hold_ms" in failure_body,
        "ConnectionSocket must log shadowed native failures with a dedicated marker",
        failures,
    )

    require("endpoint_failure_shadowed_by_success" in analyzer, "analyzer must know the native shadow marker", failures)
    require("held_by_usable_success" in analyzer, "analyzer must preserve Java usable-success hold decisions", failures)
    require("held_live_by_usable_success" in analyzer, "analyzer must explain Java live-stage holds after usable success", failures)
    require("held_live_by_current_proxy_usable" in analyzer, "analyzer must explain Java live-stage holds while the current proxy is connected", failures)
    require("held_connect_start_by_usable_success" in analyzer, "analyzer must explain Java connect-start holds after usable success", failures)
    require('"check_proxy_usable_success_hold.py"' in all_checks, "full guard suite must include usable-success hold guard", failures)

    run_analyzer_shadow_check(failures)
    run_runtime_log_visible_hold_check(failures)

    if failures:
        print("Proxy usable-success hold guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Proxy usable-success hold guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
