#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
ROTATION = MESSENGER / "ProxyRotationController.java"
ENGINE = MESSENGER / "ProxyRotationEngine.java"
STORE = MESSENGER / "ProxyRuntimeStateStore.java"
HEALTH = MESSENGER / "ProxyHealthStore.java"
STATUS = MESSENGER / "ProxyStatusMirror.java"
SCHEDULER = MESSENGER / "ProxyCheckScheduler.java"
CHECK_ALL = ROOT / "Tools/check_mtproxy_all.py"
RUNTIME_LOG_VERIFIER = ROOT / "Tools/verify_mtproxy_runtime_logs.py"


NON_PUNITIVE_ROTATION_PHASES = (
    "tcp_connect_gate",
    "connect_start",
    "socket_connect_start",
    "dns_cache_hit",
    "server_hello_hmac_ok",
    "first_tls_app_sent",
)

PUNITIVE_ROTATION_PHASES = (
    "tcp_not_connected",
    "host_resolve_failed",
    "host_resolve_timeout",
    "tcp_connected_no_pong",
    "client_hello_sent_no_server_hello",
    "server_hello_hmac_mismatch",
    "mtproxy_packet_sent_no_response",
    "post_handshake_no_appdata",
    "dropped_early_after_appdata",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


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


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def ordered(body: str, *needles: str) -> bool:
    cursor = -1
    for needle in needles:
        index = body.find(needle, cursor + 1)
        if index == -1:
            return False
        cursor = index
    return True


def runtime_log_fixture(*proxy_rotation_lines: str, include_success: bool = False) -> str:
    lines = [
        "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
        "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
        "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
        "logcat.txt:4: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
        "logcat.txt:5: 06-25 20:31:30.100 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=sberbank.dns.army:45631 key=sberbank.dns.army:45631:ee:sberbank.dns.army reason=first_tls_app_recv",
    ]
    if include_success:
        lines.append("logcat.txt:6: 06-25 20:31:30.110 proxy_control decision=visible_usable_success source=native_stage account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army")
    for index, line in enumerate(proxy_rotation_lines, start=7):
        lines.append(f"logcat.txt:{index}: {line}")
    return "\n".join(lines) + "\n"


def run_runtime_rotation_log_checks(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp)
        live_trigger = session / "live_trigger.txt"
        success_trigger = session / "success_trigger.txt"
        good_trigger = session / "good_trigger.txt"
        dns_outage_trigger = session / "dns_outage_trigger.txt"
        dns_outage_hold = session / "dns_outage_hold.txt"
        rotated_away_bad = session / "rotated_away_bad.txt"
        rotated_away_good = session / "rotated_away_good.txt"
        live_trigger.write_text(
            runtime_log_fixture(
                "06-25 20:31:31.110 proxy_rotation decision=trigger phase=tcp_connect_gate endpoint=sberbank.dns.army:45631 count=2 required=2"
            ),
            encoding="utf-8",
        )
        success_trigger.write_text(
            runtime_log_fixture(
                "06-25 20:31:31.100 proxy_rotation decision=waiting_hysteresis phase=tcp_not_connected endpoint=sberbank.dns.army:45631 count=1 required=2",
                "06-25 20:31:32.100 proxy_rotation decision=trigger phase=tcp_not_connected endpoint=sberbank.dns.army:45631 count=2 required=2",
                include_success=True,
            ),
            encoding="utf-8",
        )
        good_trigger.write_text(
            runtime_log_fixture(
                "06-25 20:32:20.100 proxy_rotation decision=waiting_hysteresis phase=tcp_not_connected endpoint=sberbank.dns.army:45631 count=1 required=2",
                "06-25 20:32:21.100 proxy_rotation decision=trigger phase=tcp_not_connected endpoint=sberbank.dns.army:45631 count=2 required=2",
            ),
            encoding="utf-8",
        )
        dns_outage_trigger.write_text(
            runtime_log_fixture(
                "06-25 20:33:00.000 D/tmessages dns_resolver fallback provider=system host=avito.mosru.v6.rocks reason=inet_UnknownHostException",
                "06-25 20:33:00.100 D/tmessages dns_resolver fallback provider=google_json_doh host=avito.mosru.v6.rocks reason=UnknownHostException",
                "06-25 20:33:00.200 D/tmessages dns_resolver fallback provider=cloudflare_json_doh host=avito.mosru.v6.rocks reason=UnknownHostException",
                "06-25 20:33:00.300 D/tmessages dns_resolver provider=chain result=resolve_failed host=avito.mosru.v6.rocks ipv4=0 ipv6=0 source=",
                "06-25 20:33:00.400 proxy_rotation decision=waiting_hysteresis phase=host_resolve_failed endpoint=avito.mosru.v6.rocks:45631 count=1 required=2",
                "06-25 20:33:00.500 proxy_rotation decision=trigger phase=host_resolve_failed endpoint=avito.mosru.v6.rocks:45631 count=2 required=2",
            ),
            encoding="utf-8",
        )
        dns_outage_hold.write_text(
            runtime_log_fixture(
                "06-25 20:33:00.000 D/tmessages dns_resolver fallback provider=system host=avito.mosru.v6.rocks reason=inet_UnknownHostException",
                "06-25 20:33:00.100 D/tmessages dns_resolver fallback provider=google_json_doh host=avito.mosru.v6.rocks reason=UnknownHostException",
                "06-25 20:33:00.200 D/tmessages dns_resolver fallback provider=cloudflare_json_doh host=avito.mosru.v6.rocks reason=UnknownHostException",
                "06-25 20:33:00.300 D/tmessages dns_resolver provider=chain result=resolve_failed host=avito.mosru.v6.rocks ipv4=0 ipv6=0 source=",
                "06-25 20:33:00.500 proxy_rotation decision=dns_outage_hold phase=host_resolve_failed endpoint=avito.mosru.v6.rocks:45631 host=avito.mosru.v6.rocks",
            ),
            encoding="utf-8",
        )
        rotated_away_bad.write_text(
            runtime_log_fixture(
                "06-25 20:34:00.000 proxy_rotation decision=waiting_hysteresis phase=client_hello_sent_no_server_hello endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army count=1 required=2",
                "06-25 20:34:00.900 proxy_rotation decision=trigger phase=client_hello_sent_no_server_hello endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army count=2 required=2",
                "06-25 20:34:01.050 proxy_control decision=visible_only source=native_stage account=0 phase=endpoint_cooldown endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
            ),
            encoding="utf-8",
        )
        rotated_away_good.write_text(
            runtime_log_fixture(
                "06-25 20:34:00.000 proxy_rotation decision=waiting_hysteresis phase=client_hello_sent_no_server_hello endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army count=1 required=2",
                "06-25 20:34:00.900 proxy_rotation decision=trigger phase=client_hello_sent_no_server_hello endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army count=2 required=2",
                "06-25 20:34:01.050 proxy_control decision=ignored_rotated_away source=native_stage account=0 phase=endpoint_cooldown endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
            ),
            encoding="utf-8",
        )
        live_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(live_trigger)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            live_result.returncode != 0 and "proxy_rotation trigger from non-punitive phase" in live_result.stderr,
            "runtime log verifier must reject proxy_rotation trigger from tcp_connect_gate/connect_start/socket_connect_start/dns_cache_hit",
            failures,
        )
        success_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(success_trigger)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            success_result.returncode != 0 and "proxy_rotation trigger held by fresh usable success" in success_result.stderr,
            "runtime log verifier must reject proxy_rotation trigger while the same endpoint has fresh usable success",
            failures,
        )
        good_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(good_trigger)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            good_result.returncode == 0,
            good_result.stderr.strip() or "runtime log verifier must accept trigger only after two punitive failures inside the window",
            failures,
        )
        dns_outage_trigger_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(dns_outage_trigger)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            dns_outage_trigger_result.returncode != 0
            and "proxy_rotation trigger during DNS outage" in dns_outage_trigger_result.stderr,
            "runtime log verifier must reject host_resolve_failed rotation while system, Google DoH, and Cloudflare DoH all fail for the same host",
            failures,
        )
        dns_outage_hold_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(dns_outage_hold)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            dns_outage_hold_result.returncode == 0,
            dns_outage_hold_result.stderr.strip() or "runtime log verifier must accept dns_outage_hold instead of host_resolve_failed rotation",
            failures,
        )
        rotated_away_bad_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(rotated_away_bad)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            rotated_away_bad_result.returncode != 0
            and "rotated-away endpoint telemetry accepted after rotation trigger" in rotated_away_bad_result.stderr,
            "runtime log verifier must reject visible live telemetry from an endpoint after proxy_rotation trigger",
            failures,
        )
        rotated_away_good_result = subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(rotated_away_good)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            rotated_away_good_result.returncode == 0,
            rotated_away_good_result.stderr.strip() or "runtime log verifier must accept ignored_rotated_away after proxy_rotation trigger",
            failures,
        )


def main() -> int:
    failures: list[str] = []
    rotation = read(ROTATION)
    engine = read(ENGINE)
    store = read(STORE)
    health = read(HEALTH)
    status = read(STATUS)
    scheduler = read(SCHEDULER)
    connections = read(CONNECTIONS)
    check_all = read(CHECK_ALL)
    policy = read(MESSENGER / "ProxyPhasePolicy.java")

    switch_to_proxy = method_body(rotation, "private void switchToProxy")
    settings_branch = rotation[rotation.find("if (id == NotificationCenter.proxySettingsChanged)"):]
    settings_branch = settings_branch[:settings_branch.find("} else if", 1)]
    on_rotation_settings = method_body(engine, "void onRotationSettingsApplied")
    on_external_settings = method_body(engine, "void onSettingsChanged")
    complete_attempt = method_body(engine, "SwitchDecision completeScheduledAttempt")
    begin_attempt = method_body(engine, "Attempt beginScheduledAttempt")
    record_switch = method_body(engine, "void recordSwitch")
    is_candidate_allowed = method_body(engine, "private boolean isCandidateAllowed")
    should_schedule_fallback = method_body(store, "public static boolean shouldScheduleFallback")
    on_native_stage = method_body(store, "public static Decision onNativeStage")
    mark_endpoint_failure = method_body(store, "public static ProxyHealthStore.EndpointFailureResult markEndpointFailure")

    require(
        ordered(
            switch_to_proxy,
            "engine.recordSwitch(info)",
            "postNotificationName(NotificationCenter.proxyChangedByRotation)",
            "postNotificationName(NotificationCenter.proxySettingsChanged, ROTATION_SETTINGS_CHANGE)",
            "ConnectionsManager.setProxySettings",
        ),
        "rotation switch must record rate-limit/cycle state before notifying UI and applying native settings",
        failures,
    )
    require(
        ordered(
            settings_branch,
            "cancelScheduledSwitchRunnable();",
            "if (isRotationOwnedSettingsChange(args))",
            "engine.onRotationSettingsApplied();",
            "return;",
            "engine.onSettingsChanged();",
        ),
        "rotation-owned proxySettingsChanged must bypass external settings reset path",
        failures,
    )
    require(
        "cycle.reset()" not in on_rotation_settings
        and "switchTimes.clear()" not in on_rotation_settings
        and "triedExactKeys.clear()" not in on_rotation_settings,
        "rotation-owned settings application must preserve switch history and tried endpoints",
        failures,
    )
    require(
        "cycle.reset()" in on_external_settings,
        "external settings changes must reset rotation cycle",
        failures,
    )
    require(
        "static final class EndpointFailureResult" in health
        and "final boolean rotationAllowed" in health
        and "final int consecutiveFailures" in health
        and "final int rotationFailures" in health,
        "ProxyHealthStore must expose an internal endpoint failure result for rotation hysteresis",
        failures,
    )
    require(
        "enum EndpointLifecycle" in health
        and all(state in health for state in ("TESTING", "USABLE", "DEGRADED", "QUARANTINED", "ROTATED_AWAY")),
        "ProxyHealthStore must model endpoint lifecycle explicitly through testing/usable/degraded/quarantined/rotated-away states",
        failures,
    )
    require(
        "ROTATED_AWAY_HOLD_MS" in health
        and "quarantineExactEndpoint" in health
        and "ignoreEndpointTelemetry" in health
        and "shouldIgnoreEndpointTelemetry" in health
        and "clearRotatedAwayTelemetry" in health,
        "ProxyHealthStore must own quarantine and rotated-away telemetry hold state",
        failures,
    )
    require(
        "PUNITIVE_FAILURES_TO_ROTATE = 2" in health
        and "PUNITIVE_FAILURE_WINDOW_MS = 30 * 1000L" in health
        and "USABLE_SUCCESS_HOLD_MS = 45 * 1000L" in health,
        "rotation hysteresis must require two punitive failures inside a 30-second window with a 45-second usable-success hold",
        failures,
    )
    require(
        "public static boolean isPunitiveFailure" in policy
        and "public static boolean isLocalOrLiveNonPunitive" in policy,
        "ProxyPhasePolicy must explicitly split punitive failures from local/live non-punitive telemetry",
        failures,
    )
    for phase in NON_PUNITIVE_ROTATION_PHASES:
        require(
            phase.upper() in policy
            and f"case ProxyCheckDiagnostics.{phase.upper()}:" not in method_body(policy, "public static boolean isPunitiveFailure"),
            f"{phase} must not be treated as a punitive rotation failure",
            failures,
        )
    for phase in PUNITIVE_ROTATION_PHASES:
        require(
            f"case ProxyCheckDiagnostics.{phase.upper()}:" in method_body(policy, "public static boolean isPunitiveFailure"),
            f"{phase} must be treated as a punitive rotation failure",
            failures,
        )
    require(
        "EndpointFailureResult rememberLiveFailure" in health
        and "rotationFailures >= PUNITIVE_FAILURES_TO_ROTATE" in health,
        "live failures must update rotation hysteresis before rotation is allowed",
        failures,
    )
    require(
        "ProxyHealthStore.EndpointFailureResult failure = ProxyHealthStore.rememberLiveFailure" in store
        and "failure.rotationAllowed" in store,
        "runtime store must use health-store rotationAllowed instead of rotating on the first punitive phase",
        failures,
    )
    require(
        "public static ProxyHealthStore.EndpointFailureResult markEndpointFailure" in store
        and "EndpointFailureResult.noop" in health,
        "explicit endpoint failures must return a health-store failure result for scheduled rotation attempts",
        failures,
    )
    require(
        "ProxyHealthStore.shouldIgnoreEndpointTelemetry(event.endpointKey, event.timestamp)" in on_native_stage
        and "decision=ignored_rotated_away" in on_native_stage,
        "native stages from rotated-away endpoints must be ignored before they can update visible/backoff state",
        failures,
    )
    require(
        ordered(
            should_schedule_fallback,
            "boolean result = candidate && failure.rotationAllowed;",
            "ProxyHealthStore.quarantineExactEndpoint(currentProxy, normalized, now);",
            "ProxyHealthStore.ignoreEndpointTelemetry(endpointKey, now);",
            "ProxyCheckScheduler.cancelEndpointAttempts(endpointKey);",
            "decision=trigger",
        ),
        "fallback scheduling must quarantine the exact endpoint, ignore its late telemetry, and cancel endpoint checks before logging trigger",
        failures,
    )
    require(
        "ProxyHealthStore.quarantineExactEndpoint(proxyInfo, normalized, now)" in mark_endpoint_failure
        and "ProxyHealthStore.ignoreEndpointTelemetry(ProxyEndpointKey.liveStage(proxyInfo), now)" in mark_endpoint_failure,
        "scheduled explicit rotation failures must quarantine and ignore the rotated-away endpoint too",
        failures,
    )
    require(
        "public static int cancelEndpointAttempts(String endpointKey)" in scheduler
        and "ConnectionsManager.getInstance(request.currentAccount).cancelProxyCheck" in scheduler
        and "ProxyEndpointKey.matchesTelemetryEndpointKey" in scheduler,
        "ProxyCheckScheduler must cancel queued and active checks for a rotated-away endpoint",
        failures,
    )
    require(
        ordered(
            complete_attempt,
            "ProxyRuntimeStateStore.markEndpointFailure(currentProxy, ProxyCheckDiagnostics.CONNECTING_TIMEOUT)",
            "if (!failure.rotationAllowed)",
            "SwitchDecision.held(\"held_by_failure_hysteresis\"",
            "return selectSwitchCandidate(currentProxy, now)",
        ),
        "connecting timeout must respect failure hysteresis before selecting a fallback",
        failures,
    )
    require(
        "ProxyRuntimeStateStore.isCurrentProxyUsable(currentProxy)" in complete_attempt
        and complete_attempt.find("isCurrentProxyUsable") < complete_attempt.find("markEndpointFailure"),
        "scheduled rotation attempts must hold while the current proxy is fresh-usable or selected account is connected/updating",
        failures,
    )
    require(
        "failure.rotationAllowed" in should_schedule_fallback
        and "held_by_failure_hysteresis" in should_schedule_fallback,
        "terminal-stage fallback scheduling must wait for the health-store hysteresis threshold",
        failures,
    )
    require(
        "ProxyPhasePolicy.isPunitiveFailure(normalized)" in should_schedule_fallback
        and "decision=ignored_non_punitive" in should_schedule_fallback
        and "decision=held_by_usable_success" in should_schedule_fallback
        and "decision=dns_outage_hold" in should_schedule_fallback
        and "decision=waiting_hysteresis" in should_schedule_fallback
        and "decision=trigger" in should_schedule_fallback,
        "fallback scheduling must log explicit proxy_rotation decisions and reject non-punitive or DNS-outage phases before hysteresis",
        failures,
    )
    require(
        "DnsOutageState" in store
        and "recordDnsResolverProviderFailure" in store
        and "recordDnsResolveChainFailure" in store
        and "recordDnsResolveSuccess" in store
        and "isDnsGlobalOutage" in store,
        "runtime store must track per-host DNS outage state from resolver-chain failures",
        failures,
    )
    require(
        "shouldHoldHostResolveFailureByDnsOutage(currentProxy, event.phase, event.timestamp)" in on_native_stage
        and ordered(
            on_native_stage,
            "shouldHoldHostResolveFailureByDnsOutage(currentProxy, event.phase, event.timestamp)",
            "decision=dns_outage_hold",
            "ProxyStatusMirror.mirrorVisiblePhase",
            "ProxyHealthStore.rememberLiveFailure",
        ),
        "native host_resolve_failed must be held by DNS outage before visible overwrite, endpoint backoff, or rotation",
        failures,
    )
    require(
        "shouldHoldHostResolveFailureByDnsOutage(proxyInfo, normalized, now)" in mark_endpoint_failure
        and ordered(
            mark_endpoint_failure,
            "shouldHoldHostResolveFailureByDnsOutage(proxyInfo, normalized, now)",
            "decision=dns_outage_hold",
            "ProxyWarmupGate.onProxyFailure",
            "ProxyHealthStore.rememberLiveFailure",
        ),
        "explicit host_resolve_failed endpoint failures must be held by DNS outage before warmup failure or endpoint backoff",
        failures,
    )
    require(
        "recordDnsResolverProviderFailure(host, resolver.name()" in connections
        and "recordDnsResolveChainFailure(host, systemFailed, googleFailed, cloudflareFailed)" in connections
        and "recordDnsResolveSuccess(host, resolver.name())" in connections
        and "recordDnsResolveSuccess(hostName, \"cache\")" in connections
        and "recordDnsResolveSuccess(host, \"cache_stale\")" in connections,
        "ConnectionsManager DNS resolver chain must publish provider failures, full-chain failures, and cache/stale/success recovery to the runtime store",
        failures,
    )
    require(
        "cycle.triedExactKeys.add(proxyExactKey)" in begin_attempt
        and "cycle.triedExactKeys.add(exactKey)" in record_switch
        and "!cycle.triedExactKeys.contains(exactKey)" in is_candidate_allowed,
        "rotation cycle must remember attempted endpoints and reject retries within the same cycle",
        failures,
    )
    require(
        "cycle.switchTimes.addLast(now)" in record_switch
        and "cycle.switchTimes.size() >= MAX_SWITCHES_PER_WINDOW" in engine
        and "decision = \"rate_limited\"" in engine,
        "rotation must enforce a real switch rate-limit window",
        failures,
    )
    require(
        "HashMap<String, EndpointState> endpointStates" in health
        and "endpointStates" not in store,
        "endpoint health state must live only in ProxyHealthStore, not the runtime facade",
        failures,
    )
    require(
        all(needle in status for needle in (
            ".lastCheckDiagnostic =",
            ".lastCheckDiagnosticTime =",
            ".available =",
            ".availableCheckTime =",
            ".checking =",
            ".proxyCheckPingId =",
            ".ping =",
        )),
        "ProxyStatusMirror must own all runtime ProxyInfo UI-state writes",
        failures,
    )
    require(
        all(needle not in store for needle in (
            ".lastCheckDiagnostic =",
            ".lastCheckDiagnosticTime =",
            ".available =",
            ".availableCheckTime =",
            ".checking =",
            ".proxyCheckPingId =",
            ".ping =",
        )),
        "ProxyRuntimeStateStore facade must not write runtime ProxyInfo UI-state directly",
        failures,
    )
    require(
        '"check_proxy_rotation_behavior.py"' in check_all,
        "full MTProxy guard suite must include rotation behavior scenarios",
        failures,
    )
    run_runtime_rotation_log_checks(failures)

    if failures:
        print("Proxy rotation behavior guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Proxy rotation behavior guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
