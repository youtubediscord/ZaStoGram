#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "Tools"
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
TGNET_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
JNI = ROOT / "TMessagesProj/jni"
TGNET = JNI / "tgnet"

RUNTIME_LOG_VERIFIER = TOOLS / "verify_mtproxy_runtime_logs.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def run_verifier(markers: str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write(markers)
        path = Path(handle.name)
    try:
        return subprocess.run(
            [sys.executable, str(RUNTIME_LOG_VERIFIER), str(path)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def base_log(*lines: str) -> str:
    result = [
        "logcat.txt:1: 06-30 13:59:30.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
        "logcat.txt:2: 06-30 13:59:30.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
        "logcat.txt:3: 06-30 13:59:30.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
        "logcat.txt:4: 06-30 13:59:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
        "logcat.txt:5: 06-30 13:59:30.100 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=sberbank.dns.army:45631 key=sberbank.dns.army:45631:ee:sberbank.dns.army reason=first_tls_app_recv",
        "logcat.txt:6: 06-30 13:59:30.110 proxy_control decision=visible_usable_success source=native_stage origin=active_socket account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
    ]
    for index, line in enumerate(lines, start=7):
        result.append(f"logcat.txt:{index}: {line}")
    return "\n".join(result) + "\n"


def verify_runtime_contract(failures: list[str]) -> None:
    probe_wait = run_verifier(
        base_log(
            "06-30 14:00:00.000 connection(0x1) mtproxy_startup probe_start key=fast2.mtproxy.zip:443:secret_hash=1111111111111111:xapi.ozon.ru endpoint=fast2.mtproxy.zip:443:ee:xapi.ozon.ru generation=1",
            "06-30 14:00:00.010 connection(0x2) mtproxy_startup probe_join key=fast2.mtproxy.zip:443:secret_hash=1111111111111111:xapi.ozon.ru endpoint=fast2.mtproxy.zip:443:ee:xapi.ozon.ru owner_generation=1",
            "06-30 14:00:00.020 proxy_control decision=telemetry_only source=native_stage origin=active_socket account=1 phase=mtproxy_probe_wait endpoint=fast2.mtproxy.zip:443:ee:xapi.ozon.ru probe=fast2.mtproxy.zip:443:secret_hash=1111111111111111:xapi.ozon.ru",
            "06-30 14:00:00.030 connection(0x1) mtproxy_startup client_hello_sent bytes=512 expected=512 domain_len=13",
            "06-30 14:00:00.040 connection(0x1) mtproxy_startup recipe_failed key=fast2.mtproxy.zip:443:ee:xapi.ozon.ru recipe_key=fast2.mtproxy.zip:443:secret_hash=1111111111111111:xapi.ozon.ru phase=faketls_server_hello_wait_timeout evidence=no_bytes_after_client_hello response_bytes=0 next=legacy_no_grease",
        )
    )
    require(
        probe_wait.returncode == 0,
        probe_wait.stderr.strip() or "runtime verifier must accept probe wait as telemetry-only joined socket state",
        failures,
    )

    bad_eof_alias = run_verifier(
        base_log(
            "06-30 14:01:00.000 connection(0x1) mtproxy_startup client_hello_sent bytes=512 expected=512 domain_len=13",
            "06-30 14:01:00.010 connection(0x1) mtproxy_startup recv_eof proxy_state=11 tls_state=0",
            "06-30 14:01:00.020 connection(0x1) mtproxy_startup close_diagnostic phase=true_client_hello_timeout",
        )
    )
    require(
        bad_eof_alias.returncode != 0
        and "server_closed_after_client_hello" in bad_eof_alias.stderr,
        "runtime verifier must reject EOF-after-ClientHello being reported as true_client_hello_timeout",
        failures,
    )

    good_exhaustion = run_verifier(
        base_log(
            "06-30 14:02:00.000 connection(0x1) mtproxy_startup recipe_exhausted key=fast2.mtproxy.zip:443:ee:xapi.ozon.ru recipe_key=fast2.mtproxy.zip:443:secret_hash=1111111111111111:xapi.ozon.ru failed_phase=faketls_server_hello_wait_timeout evidence=no_bytes_after_client_hello response_bytes=0 next=handshake_profiles_exhausted generation=3",
            "06-30 14:02:00.010 proxy_control decision=held_by_failure_hysteresis source=native_stage origin=active_socket account=0 phase=handshake_profiles_exhausted endpoint=fast2.mtproxy.zip:443:ee:xapi.ozon.ru failures=1",
        )
    )
    require(
        good_exhaustion.returncode == 0,
        good_exhaustion.stderr.strip() or "runtime verifier must accept recipe exhaustion as recovery backoff/hysteresis, not terminal quarantine",
        failures,
    )


def main() -> int:
    failures: list[str] = []
    cmake = read(JNI / "CMakeLists.txt")
    coordinator_h = read(TGNET / "MtProxyProbeCoordinator.h")
    coordinator_cpp = read(TGNET / "MtProxyProbeCoordinator.cpp")
    socket_h = read(TGNET / "ConnectionSocket.h")
    socket_cpp = read(TGNET / "ConnectionSocket.cpp")
    endpoint_policy = read(TGNET / "MtProxyEndpointPolicy.cpp")
    timeline_h = read(TGNET / "MtProxyStartupTimeline.h")
    timeline_cpp = read(TGNET / "MtProxyStartupTimeline.cpp")
    diagnostics = read(MESSENGER / "ProxyCheckDiagnostics.java")
    phase_policy = read(MESSENGER / "ProxyPhasePolicy.java")
    runtime = read(MESSENGER / "ProxyRuntimeStateStore.java")
    event = read(MESSENGER / "ProxyConnectionEvent.java")
    java_connections = read(TGNET_JAVA)
    manager_h = read(TGNET / "ConnectionsManager.h")
    manager_cpp = read(TGNET / "ConnectionsManager.cpp")
    wrapper = read(JNI / "TgNetWrapper.cpp")
    phase_contract = read(TOOLS / "mtproxy_phase_contract.py")
    analyzer = read(TOOLS / "analyze_mtproxy_markers.py")
    verifier = read(RUNTIME_LOG_VERIFIER)

    require("tgnet/MtProxyProbeCoordinator.cpp" in cmake, "CMake must compile MtProxyProbeCoordinator.cpp", failures)
    require("class MtProxyProbeCoordinator" in coordinator_h, "coordinator header must declare MtProxyProbeCoordinator", failures)
    require("enum class DecisionKind" in coordinator_h and "StartOwner" in coordinator_h and "JoinExisting" in coordinator_h and "UseWorkingRecipe" in coordinator_h and "ProfilesExhaustedBackoff" in coordinator_h, "coordinator must expose owner/join/working/exhausted-backoff decisions", failures)
    require("struct ProbeKey" in coordinator_h and "secret_hash" in coordinator_cpp, "coordinator must key exact config by host:port + secret_hash + SNI", failures)
    require("beginOrJoin" in coordinator_h and "beginOrJoin" in coordinator_cpp, "coordinator must implement beginOrJoin", failures)
    require("state.status == ProbeStatus::WORKING_RECIPE_FOUND" in coordinator_cpp, "working recipe reuse must also cover the successful default level-0 recipe", failures)
    require("completeFailure" in coordinator_h and "completeSuccess" in coordinator_h and "completeProfilesExhausted" in coordinator_h, "coordinator must own recipe success/failure/exhaustion transitions", failures)
    require("MT_PROXY_PROBE_EXHAUSTED_HOLD_MS" in coordinator_cpp and "30 * 1000" in coordinator_cpp, "profile exhaustion must be a short recovery debounce, not a 15-minute unsupported quarantine", failures)
    require("ProbeStatus::PROFILES_EXHAUSTED" in coordinator_cpp and "ProbeStatus::UNSUPPORTED" not in coordinator_cpp, "coordinator must model recipe exhaustion as recovery state, not unsupported terminal state", failures)
    require("state.cursor = MtProxyAdaptivePolicy::initialCursor(state.allowedSniVariants)" in coordinator_cpp, "expired profile-exhaustion hold must reset the recipe cursor for a fresh recovery cycle", failures)
    require("RecipeCursor" in coordinator_cpp and "workingRecipe" in coordinator_cpp and "lastRecipeDiagnostic" in coordinator_cpp, "recipe ladder state must live in coordinator as a cursor and full working recipe", failures)

    require("MtProxyProbeCoordinator.h" in socket_cpp and "mtProxyProbeBeginOrJoin" in socket_cpp, "ConnectionSocket must delegate probe admission to coordinator", failures)
    require("MtProxyStartupPhase::ProbeWait" in timeline_h and "mtproxy_probe_wait" in timeline_cpp, "startup timeline must model probe wait as a pre-TCP local wait", failures)
    require("MT_PROXY_HANDSHAKE_TIMER_PROBE_WAIT" in socket_cpp, "ConnectionSocket must poll joined probes by timer before opening a socket", failures)
    require("currentMtProxyProbeKey" in socket_h + socket_cpp, "ConnectionSocket must store the active probe key separately from public endpoint key", failures)
    require("probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::JoinExisting" in socket_cpp, "joiners must enter probe wait instead of opening TCP", failures)
    require("probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::ProfilesExhaustedBackoff" in socket_cpp, "profile exhaustion backoff must stop before TCP/socket setup", failures)
    require("probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::UseWorkingRecipe" in socket_cpp, "working recipe must be reused before running the ladder", failures)
    open_connection_start = socket_cpp.find("void ConnectionSocket::openConnection(std::string address")
    open_connection_end = socket_cpp.find("void ConnectionSocket::openConnectionInternal(bool ipv6)", open_connection_start)
    open_connection_body = socket_cpp[open_connection_start:open_connection_end]
    direct_start = open_connection_body.find('setProxyAuthState(0, "direct_setup")')
    proxy_probe = open_connection_body.find("mtProxyProbeBeginOrJoin")
    proxy_socket = open_connection_body.find("create_proxy_socket")
    direct_probe = open_connection_body.find("mtProxyProbeBeginOrJoin", direct_start)
    direct_socket = open_connection_body.find("create_direct_socket", direct_start)
    require(
        proxy_probe >= 0
        and proxy_socket >= 0
        and proxy_probe < proxy_socket,
        "FakeTLS probe join must happen before proxy socket creation",
        failures,
    )
    require(
        direct_start >= 0
        and direct_probe >= 0
        and direct_socket >= 0
        and direct_probe < direct_socket,
        "FakeTLS probe join must happen before direct socket creation",
        failures,
    )
    require("owner_generation" in socket_cpp and "ignored_cancelled_generation" in socket_cpp, "native sockets must log generation-aware joins and cancellations", failures)
    require("working_recipe_cached" in socket_cpp and "working_recipe_cached" in analyzer, "owner success must emit a working_recipe_cached marker for later reuse proof", failures)

    require("recipeLevelForEndpoint" not in socket_cpp and "recordFailure(context, phase" not in socket_cpp, "ConnectionSocket must not mutate recipe ladder through MtProxyEndpointPolicy", failures)
    require("failureNeedsRecipe" not in endpoint_policy, "endpoint cooldown policy must not own FakeTLS recipe progression", failures)

    for phase in ("mtproxy_probe_wait", "server_closed_after_client_hello", "faketls_server_hello_wait_timeout", "unrecognized_response_after_client_hello"):
        require(phase in diagnostics, f"ProxyCheckDiagnostics must expose {phase}", failures)
        require(phase in phase_policy, f"ProxyPhasePolicy must classify {phase}", failures)
        require(phase in phase_contract, f"phase contract must include {phase}", failures)
        require(phase in analyzer, f"analyzer must understand {phase}", failures)
    require("if (proxyAuthState == 11 && proxyHandshakeClientHelloSentTime != 0 && bytesRead == 0)" in socket_cpp and "server_closed_after_client_hello" in socket_cpp, "EOF after ClientHello with zero bytes must become server_closed_after_client_hello", failures)
    require(
        "proxyCheckDiagnostic = \"faketls_server_hello_wait_timeout\"" in socket_cpp
        or "proxyCheckDiagnostic = MtProxyPhase::FaketlsServerHelloWaitTimeout" in socket_cpp,
        "no-byte ServerHello deadline must use faketls_server_hello_wait_timeout",
        failures,
    )
    require("true_client_hello_timeout" in analyzer and "legacy alias" in analyzer, "analyzer must keep true_client_hello_timeout only as a legacy alias", failures)

    require("probeKey" in event and "probeKey" in wrapper and "probeKey" in runtime, "native stage events must carry probeKey through Java runtime", failures)
    require("native_cancelProxyEndpointAttempts" in java_connections and "probeKey" in java_connections, "Java cancellation API must pass probeKey when present", failures)
    require("cancelProxyEndpointAttempts" in manager_h and "probeKey" in manager_cpp, "native cancellation must match both endpointKey and probeKey", failures)
    require("matchesMtProxyProbeKey" in socket_h and "matchesMtProxyProbeKey" in socket_cpp, "ConnectionSocket must match cancellation by probeKey", failures)
    require("handshake_profiles_exhausted" in verifier and "probeKey" in verifier, "runtime verifier must understand profile exhaustion as a probe-keyed recovery failure", failures)
    require(
        "next=unsupported_for_current_client" not in socket_cpp
        and 'proxyCheckDiagnostic = "unsupported_for_current_client"' not in socket_cpp
        and 'publishProxyConnectionStage("unsupported_for_current_client")' not in socket_cpp,
        "ConnectionSocket must not publish unsupported_for_current_client from recipe exhaustion",
        failures,
    )

    # --- Commit 1: bounded PROBING lifetime + recipe-progress self-connect budget + reaper (liveness) ---
    require(
        "MT_PROXY_PROBE_OWNER_DEADLINE_MS" in coordinator_cpp and "Connection.cpp" in coordinator_cpp,
        "PROBING owners must carry a bounded deadline sized against the worst owner attempt (Connection.cpp)",
        failures,
    )
    require("MT_PROXY_PROBE_JOIN_TOTAL_BUDGET_MS" in coordinator_cpp, "joiners must have a bounded self-connect budget", failures)
    require("probingUntil" in coordinator_cpp, "coordinator must track a per-owner PROBING deadline (probingUntil)", failures)
    begin_or_join_start = coordinator_cpp.find("MtProxyProbeCoordinator::beginOrJoin")
    begin_or_join_end = coordinator_cpp.find("MtProxyProbeCoordinator::completeFailure", begin_or_join_start)
    begin_or_join_body = coordinator_cpp[begin_or_join_start:begin_or_join_end]
    reclaim_idx = begin_or_join_body.find("state.probingUntil <= now")
    join_existing_idx = begin_or_join_body.find("DecisionKind::JoinExisting")
    require(
        reclaim_idx >= 0 and join_existing_idx >= 0 and reclaim_idx < join_existing_idx,
        "beginOrJoin must reclaim an expired/ownerless PROBING owner before any JoinExisting decision",
        failures,
    )
    require(
        "state.cursor.generation != state.joinBudgetAnchorCursorGen" in begin_or_join_body,
        "join budget must be anchored to recipe-cursor progress, not bare generation",
        failures,
    )
    require("reapExpired" not in begin_or_join_body, "the reaper must run on the network-thread tick, not inside beginOrJoin", failures)
    require(
        "void MtProxyProbeCoordinator::touchOwner" in coordinator_cpp
        and "void MtProxyProbeCoordinator::reapExpired" in coordinator_cpp,
        "coordinator must define the owner heartbeat (touchOwner) and the deadline reaper (reapExpired)",
        failures,
    )
    require("MtProxyProbeCoordinator::reapExpired(now)" in manager_cpp, "ConnectionsManager::select must reap expired PROBING owners on its monotonic tick", failures)
    require(
        "mtProxyProbeHeartbeat" in socket_cpp and "mtProxyProbeHeartbeat" in socket_h,
        "ConnectionSocket must heartbeat the probe owner at handshake milestones (socket_connected/client_hello_sent)",
        failures,
    )

    # --- Commit 2: opaque uint64 ownership token + key-independent RAII lease (leak/ABA hardening) ---
    require(
        "uint64_t ownerToken" in coordinator_cpp and "uint64_t callerToken" in coordinator_h and "const void *owner" not in coordinator_h,
        "probe ownership must be an opaque uint64 token, not a raw (ABA-prone) pointer",
        failures,
    )
    require(
        "mtProxyProbeOwnerTokenSeq" in coordinator_cpp and coordinator_cpp.count("mtProxyProbeOwnerTokenSeq++") == 1,
        "owner tokens must be minted in exactly one place",
        failures,
    )
    enter_start = coordinator_cpp.find("static uint64_t enterProbing(")
    enter_end = coordinator_cpp.find("MtProxyProbeCoordinator::Decision MtProxyProbeCoordinator::beginOrJoin", enter_start)
    enter_body = coordinator_cpp[enter_start:enter_end] if enter_start >= 0 else ""
    require(enter_start >= 0 and "mtProxyProbeOwnerTokenSeq++" in enter_body, "the owner-token mint must live inside enterProbing", failures)
    require(
        coordinator_cpp.count("status = ProbeStatus::PROBING") == 1 and "status = ProbeStatus::PROBING" in enter_body,
        "status = PROBING must be written only inside enterProbing (single funnel)",
        failures,
    )
    require(
        "publishProxyConnectionStage" not in coordinator_cpp and "delegate->" not in coordinator_cpp and "CallStatic" not in coordinator_cpp,
        "coordinator must make no JNI/delegate upcall under its mutex (strict leaf)",
        failures,
    )
    require("pthread_mutex_destroy" not in coordinator_cpp, "coordinator mutex must never be destroyed", failures)
    require(".erase(" in coordinator_cpp, "reapExpired must bound the probe-state map by erasing dead entries", failures)
    require(
        "completeMtProxyProbeOwner" not in socket_cpp and "completeMtProxyProbeOwner" not in socket_h,
        "the leak-prone, key-dependent completeMtProxyProbeOwner must be removed in favour of the RAII lease",
        failures,
    )
    require(
        "acquireMtProxyProbeLease" in socket_cpp and "releaseMtProxyProbeLease" in socket_cpp
        and "mtProxyProbeOwnerToken" in socket_h and "mtProxyProbeLeaseKey" in socket_cpp,
        "ConnectionSocket must hold a token+key lease released key-independently",
        failures,
    )
    open_conn_idx = socket_cpp.find("void ConnectionSocket::openConnection(std::string address")
    open_release_idx = socket_cpp.find("releaseMtProxyProbeLease()", open_conn_idx)
    open_scrub_idx = socket_cpp.find('currentMtProxyProbeKey = ""', open_conn_idx)
    require(
        open_conn_idx >= 0 and open_release_idx >= 0 and open_scrub_idx >= 0 and open_release_idx < open_scrub_idx,
        "openConnection must release the probe lease before scrubbing the probe key",
        failures,
    )
    close_idx = socket_cpp.find("void ConnectionSocket::closeSocket(")
    close_recfail_idx = socket_cpp.find("recordMtProxyEndpointFailure(terminalDiagnostic", close_idx)
    close_release_idx = socket_cpp.find("releaseMtProxyProbeLease()", close_idx)
    require(
        close_idx >= 0 and close_recfail_idx >= 0 and close_release_idx >= 0 and close_recfail_idx < close_release_idx,
        "closeSocket must record the failure while the token is live, then release the lease (no phantom re-mint)",
        failures,
    )
    # --- Commit 3: admission_queue JNI out of lock + probeKey-only Java cancel ---
    scheduler_cpp = read(TGNET / "MtProxyHandshakeScheduler.cpp")
    admq_idx = socket_cpp.find('publishProxyConnectionStage("admission_queue")')
    admit_idx = socket_cpp.find("mtProxyHandshakeSchedulerAdmit(request)")
    require(
        "proxyHandshakeSchedulerMutex" not in socket_cpp
        and "proxyHandshakeSchedulerMutex" in scheduler_cpp
        and "decision.publishQueue" in socket_cpp
        and admit_idx >= 0
        and admq_idx >= 0
        and admit_idx < admq_idx
        and "publishProxyConnectionStage" not in scheduler_cpp,
        "admission_queue JNI publish must be hoisted out of proxyHandshakeSchedulerMutex (lock-order-inversion safety)",
        failures,
    )
    require(
        "TextUtils.isEmpty(endpointKey) && TextUtils.isEmpty(probeKey)" in java_connections,
        "Java cancelProxyEndpointAttempts must accept a probeKey-only kill-switch",
        failures,
    )

    verify_runtime_contract(failures)

    if failures:
        print("MTProxy probe coordinator guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    print("MTProxy probe coordinator guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
