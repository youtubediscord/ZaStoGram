#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
STORE = MESSENGER / "ProxyRuntimeStateStore.java"
REDUCER = MESSENGER / "ProxyEventReducer.java"
VISIBLE_STORE = MESSENGER / "ProxyVisibleStateStore.java"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"
RUNTIME_LOG_VERIFIER = ROOT / "Tools/verify_mtproxy_runtime_logs.py"

DNS_TELEMETRY_PHASES = (
    ("host_resolve_start", "HOST_RESOLVE_START"),
    ("dns_coalesce_wait", "DNS_COALESCE_WAIT"),
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


def runtime_lines(proxy_control_tail: str) -> str:
    return (
        "\n".join(
            [
                "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) connecting via proxy sberbank.dns.army:45631 secret[34] secret_kind=ee",
                proxy_control_tail,
                "logcat.txt:10: 06-25 20:31:31.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
                "logcat.txt:11: 06-25 20:31:31.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
                "logcat.txt:12: 06-25 20:31:31.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
                "logcat.txt:13: 06-25 20:31:31.030 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
                "logcat.txt:14: 06-25 20:31:31.040 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=sberbank.dns.army:45631 key=sberbank.dns.army:45631:ee:sberbank.dns.army reason=first_tls_app_recv",
            ]
        )
        + "\n"
    )


def run_runtime_log_checks(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp)
        fast_bad = session / "fast_bad_markers.txt"
        fast_good = session / "fast_good_markers.txt"
        slow_good = session / "slow_good_markers.txt"
        fast_bad.write_text(
            runtime_lines(
                "\n".join(
                    [
                        "logcat.txt:2: 06-25 20:31:30.010 proxy_control decision=visible_only source=native_stage account=0 phase=host_resolve_start endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                        "logcat.txt:3: 06-25 20:31:30.120 proxy_control decision=visible_only source=native_stage account=0 phase=socket_connect_start endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    ]
                )
            ),
            encoding="utf-8",
        )
        fast_good.write_text(
            runtime_lines(
                "\n".join(
                    [
                        "logcat.txt:2: 06-25 20:31:30.010 proxy_control decision=telemetry_only source=native_stage account=0 phase=host_resolve_start endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                        "logcat.txt:3: 06-25 20:31:30.120 proxy_control decision=visible_only source=native_stage account=0 phase=socket_connect_start endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    ]
                )
            ),
            encoding="utf-8",
        )
        slow_good.write_text(
            runtime_lines(
                "\n".join(
                    [
                        "logcat.txt:2: 06-25 20:31:30.010 proxy_control decision=telemetry_only source=native_stage account=0 phase=dns_coalesce_wait endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                        "logcat.txt:3: 06-25 20:31:30.860 proxy_control decision=visible_delayed_dns source=native_stage account=0 phase=dns_coalesce_wait endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    ]
                )
            ),
            encoding="utf-8",
        )

        fast_bad_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(fast_bad)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            fast_bad_result.returncode != 0
            and "short DNS telemetry mirrored as visible" in fast_bad_result.stderr,
            "runtime log verifier must reject visible_only DNS telemetry that is followed by TCP within the debounce window",
            failures,
        )

        for path, message in (
            (fast_good, "runtime log verifier must allow fast DNS telemetry when it stays telemetry_only"),
            (slow_good, "runtime log verifier must allow DNS to become visible after debounce expiry"),
        ):
            result = subprocess.run(
                [sys.executable, str(RUNTIME_LOG_VERIFIER), str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            require(result.returncode == 0, result.stderr.strip() or message, failures)


def main() -> int:
    failures: list[str] = []
    store = read(STORE)
    reducer = read(REDUCER)
    visible_store = read(VISIBLE_STORE)
    analyzer = read(ANALYZER)
    on_native_stage = method_body(reducer, "static ProxyRuntimeStateStore.Decision reduce")
    schedule_helper = method_body(visible_store, "static void scheduleDnsVisiblePhase")
    promote_helper = method_body(visible_store, "private static void promotePendingDnsVisiblePhase")
    delay_helper = method_body(visible_store, "static boolean shouldDelayDnsVisiblePhase")
    clear_helper = method_body(visible_store, "static void clearPendingDnsVisiblePhase")

    require("DNS_VISIBLE_DELAY_MS = 800L" in visible_store, "visible state store must debounce visible DNS telemetry for 800ms", failures)
    require("pendingDnsVisibleGeneration" in visible_store, "visible state store must token pending DNS visible updates by generation", failures)
    require(
        delay_helper
        and all(f"ProxyCheckDiagnostics.{constant}" in delay_helper for _, constant in DNS_TELEMETRY_PHASES),
        "visible state store must identify host_resolve_start and dns_coalesce_wait as delayed DNS telemetry",
        failures,
    )
    require(
        schedule_helper
        and "AndroidUtilities.runOnUIThread" in schedule_helper
        and "promotePendingDnsVisiblePhase" in schedule_helper
        and promote_helper
        and "ProxyStatusMirror.mirrorVisiblePhase" in promote_helper
        and "decision=visible_delayed_dns" in promote_helper,
        "visible state store must schedule a delayed visible DNS write instead of mirroring immediately",
        failures,
    )
    require(
        clear_helper
        and "pendingDnsVisibleGeneration++" in clear_helper
        and "pendingDnsVisibleEndpointKey" in clear_helper,
        "visible state store must clear stale pending DNS visible writes when a later endpoint event arrives",
        failures,
    )
    for phase, constant in DNS_TELEMETRY_PHASES:
        require(
            f"ProxyCheckDiagnostics.{constant}" in visible_store
            and f"decision=telemetry_only" in reducer,
            f"{phase} must be logged as telemetry_only before delayed visible promotion",
            failures,
        )

    delay_idx = on_native_stage.find("ProxyVisibleStateStore.shouldDelayDnsVisiblePhase(event.phase)")
    dns_connection_hold_idx = on_native_stage.find("shouldKeepConnectionNotStartedTelemetryOnlyByDnsOutage(currentProxy, event.phase, event.timestamp)")
    visible_write_idx = on_native_stage.find("if (selectedAccountStage && verdict.canOverwriteVisible)")
    require(
        delay_idx >= 0
        and visible_write_idx >= 0
        and delay_idx < visible_write_idx
        and 'return new ProxyRuntimeStateStore.Decision("telemetry_only"' in on_native_stage,
        "DNS telemetry debounce must run before the generic visible mirror branch",
        failures,
    )
    require(
        dns_connection_hold_idx >= 0
        and visible_write_idx >= 0
        and dns_connection_hold_idx < visible_write_idx
        and "ProxyCheckDiagnostics.CONNECTION_NOT_STARTED" in store
        and "previous_dns_outage" in store
        and 'return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, false, false, false)' in on_native_stage,
        "connection_not_started after a DNS outage/resolve failure must stay telemetry_only before visible mirror/backoff/rotation",
        failures,
    )
    require(
        "telemetry_only" in analyzer
        and "visible_delayed_dns" in analyzer,
        "analyzer help must explain DNS telemetry-only and delayed-visible decisions",
        failures,
    )
    run_runtime_log_checks(failures)

    if failures:
        print("Proxy DNS visible debounce guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Proxy DNS visible debounce guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
