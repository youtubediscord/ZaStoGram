#!/usr/bin/env python3
from pathlib import Path
import re
import sys

from mtproxy_phase_contract import java_visible_live_phases, native_phase_names


ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "socket": ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp",
    "endpoint_policy": ROOT / "TMessagesProj/jni/tgnet/MtProxyEndpointPolicy.cpp",
    "probe_coordinator": ROOT / "TMessagesProj/jni/tgnet/MtProxyProbeCoordinator.cpp",
    "recovery_policy": ROOT / "TMessagesProj/jni/tgnet/MtProxyRecoveryPolicy.cpp",
    "data_path_shaper": ROOT / "TMessagesProj/jni/tgnet/MtProxyDataPathShaper.cpp",
    "socket_header": ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h",
    "machine_header": ROOT / "TMessagesProj/jni/tgnet/ConnectionSocketStateMachine.h",
    "connection": ROOT / "TMessagesProj/jni/tgnet/Connection.cpp",
    "connection_header": ROOT / "TMessagesProj/jni/tgnet/Connection.h",
    "diagnostics": ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckDiagnostics.java",
    "values": ROOT / "TMessagesProj/src/main/res/values/strings.xml",
    "values_ru": ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml",
    "analyzer": ROOT / "Tools/analyze_mtproxy_markers.py",
    "native_phase_contract": ROOT / "TMessagesProj/jni/tgnet/MtProxyPhaseContract.h",
}

REQUIRED_PHASES = sorted(java_visible_live_phases() & native_phase_names())


def read(name):
    return FILES[name].read_text(encoding="utf-8", errors="replace")


def require(condition, message):
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def native_phase_constants():
    return {
        value: name
        for name, value in re.findall(r'constexpr const char \*([A-Za-z0-9_]+)\s*=\s*"([a-z0-9_]+)"', read("native_phase_contract"))
    }


def has_phase(source, phase, constants):
    constant = constants.get(phase)
    return f'"{phase}"' in source or (constant is not None and f"MtProxyPhase::{constant}" in source)


def main():
    socket = read("socket")
    endpoint_policy = read("endpoint_policy")
    probe_coordinator = read("probe_coordinator")
    recovery_policy = read("recovery_policy")
    data_path_shaper = read("data_path_shaper")
    header = read("socket_header")
    machine_header = read("machine_header")
    socket_state_header = header + "\n" + machine_header
    connection = read("connection")
    connection_header = read("connection_header")
    diagnostics = read("diagnostics")
    analyzer = read("analyzer")
    values = read("values")
    values_ru = read("values_ru")
    phase_constants = native_phase_constants()
    combined = "\n".join([socket, socket_state_header, connection, connection_header, diagnostics, analyzer, values, values_ru])

    require(
        "MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF" in socket,
        "ConnectionSocket must have a separate endpoint cooldown timer before TCP connect",
    )
    require(
        "MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE" in socket
        and "MT_PROXY_ENDPOINT_DNS_COALESCE_MS" in endpoint_policy,
        "ConnectionSocket must have a short DNS coalescing timer before delegate host resolve",
    )
    require(
        "MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE" in socket
        and "MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_MS" in endpoint_policy,
        "ConnectionSocket must have a short active-TCP-connect gate for repeated endpoint starts",
    )
    require(
        "MtProxyEndpointResilienceState" in endpoint_policy and "proxyEndpointResilience" in endpoint_policy,
        "MtProxyEndpointPolicy must keep per-endpoint resilience state outside FakeTLS admission",
    )
    require(
        "currentMtProxyEndpointKey" in combined and "proxyEndpointBackoffReady" in combined,
        "ConnectionSocket must remember endpoint circuit-breaker state per socket",
    )
    require(
        "proxyEndpointTcpConnectActive" in combined
        and "proxyEndpointTcpConnectReady" in combined,
        "ConnectionSocket must remember active TCP connect gate state per socket",
    )
    require(
        "proxyEndpointTcpConnectGatePublished" in combined,
        "ConnectionSocket must remember whether TCP gate wait was already published to the UI for this socket",
    )
    require(
        "proxyHandshakeAdmissionQueuePublished" in combined,
        "ConnectionSocket must remember whether admission queue wait was already published to the UI for this socket",
    )
    require(
        "currentMtProxyDnsCacheKey" in combined,
        "ConnectionSocket must keep a DNS cache key separate from the MTProxy secret/SNI endpoint key",
    )
    require(
        "currentMtProxyNetworkEndpointKey" in combined,
        "ConnectionSocket must keep a host/port network endpoint key for pre-TLS DNS/TCP failures",
    )
    require(
        "proxyEndpointDnsCoalesceReady" in combined,
        "ConnectionSocket must remember when a DNS coalescing delay has already fired for this socket",
    )
    require(
        "scheduleMtProxyEndpointCircuitBreakerIfNeeded(ipv6)" in socket,
        "openConnectionInternal must run endpoint circuit breaker before TCP connect",
    )
    require(
        "if (isCurrentMtProxyConnection() && scheduleMtProxyEndpointCircuitBreakerIfNeeded(ipv6))" in socket,
        "endpoint circuit breaker must cover all MTProxy secret kinds, not only ee FakeTLS",
    )
    require(
        "if (isCurrentMtProxyConnection() && scheduleMtProxyEndpointTcpConnectGateIfNeeded(ipv6))" in socket,
        "endpoint TCP connect gate must cover all MTProxy secret kinds before real connect()",
    )
    require(
        "scheduleMtProxyDnsCoalesceIfNeeded(ipv6)" in socket,
        "domain MTProxy endpoints must coalesce cold DNS resolves before calling delegate DNS",
    )
    schedule_start = socket.find("bool ConnectionSocket::scheduleMtProxyEndpointCircuitBreakerIfNeeded")
    schedule_end = socket.find("void ConnectionSocket::recordMtProxyEndpointFailure", schedule_start)
    schedule_body = socket[schedule_start:schedule_end]
    require(
        "!mtProxyConnectionPatternUsesCooldown(connectionPatternMode)" not in schedule_body,
        "endpoint circuit breaker must run in Default/Soft too; connection pattern may scale delay, not disable it",
    )
    cooldown_start = endpoint_policy.find("static int64_t cooldownMs")
    cooldown_end = endpoint_policy.find("static bool failureCanBeShadowedBySuccess", cooldown_start)
    if cooldown_end == -1:
        cooldown_end = endpoint_policy.find("bool MtProxyEndpointPolicy::extractSslipIpv4Address", cooldown_start)
    cooldown_body = endpoint_policy[cooldown_start:cooldown_end]
    require(
        "return 0;" not in cooldown_body,
        "endpoint failure recording must produce a small cooldown even in Default/Soft modes",
    )
    shadow_start = endpoint_policy.find("static bool failureCanBeShadowedBySuccess")
    shadow_end = endpoint_policy.find("bool MtProxyEndpointPolicy::extractSslipIpv4Address", shadow_start)
    shadow_body = endpoint_policy[shadow_start:shadow_end]
    require(
        "MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS" in endpoint_policy
        and "usableSuccessRemainingMsLocked" in shadow_body
        and has_phase(shadow_body, "tcp_not_connected", phase_constants)
        and has_phase(shadow_body, "tcp_connection_refused", phase_constants)
        and has_phase(shadow_body, "tcp_connect_timeout", phase_constants)
        and 'diagnostic == "true_client_hello_timeout"' in shadow_body
        and 'diagnostic == "client_hello_sent_no_server_hello"' in shadow_body
        and 'diagnostic == "mtproxy_packet_sent_no_response"' in shadow_body
        and has_phase(shadow_body, "post_handshake_no_appdata", phase_constants)
        and 'diagnostic == "dropped_early_after_appdata" || diagnostic == "dropped_after_appdata"' in shadow_body
        and "return false;" in shadow_body,
        "fresh data-path success must shadow only pre-data-path sibling failures and leave real post-data drops unshadowed",
    )
    require(
        '"mtproxy_packet_sent_no_response"' in cooldown_body
        and '"dropped_early_after_appdata"' in cooldown_body
        and "plainNoResponseFailures" in cooldown_body,
        "dd/plain MTProxy first-packet/no-response and early post-appdata drops must feed endpoint backoff",
    )
    require(
        "networkFailure" in cooldown_body
        and 'diagnostic == "host_resolve_failed"' in cooldown_body
        and 'diagnostic == "host_resolve_timeout"' in cooldown_body
        and has_phase(cooldown_body, "tcp_not_connected", phase_constants)
        and has_phase(cooldown_body, "tcp_connection_refused", phase_constants)
        and has_phase(cooldown_body, "tcp_connect_timeout", phase_constants)
        and "priority" in cooldown_body
        and "interactiveNetworkFailure" in cooldown_body
        and "MT_PROXY_ENDPOINT_INTERACTIVE_NETWORK_COOLDOWN_MAX_MS" in cooldown_body
        and "MT_PROXY_ENDPOINT_HEAVY_NETWORK_COOLDOWN_MAX_MS" in cooldown_body
        and "MT_PROXY_ENDPOINT_BROWSER_NETWORK_COOLDOWN_MAX_MS" not in cooldown_body,
        "pre-TCP host/DNS failures must use short priority-aware network cooldowns, not old long endpoint-wide waits",
    )
    require(
        "MtProxyEndpointPolicy::recordFailure" in socket
        and "priority=%d cooldown_ms" in socket,
        "endpoint failure recording must pass connection priority into cooldown calculation and log it",
    )
    require(
        "recordMtProxyEndpointFailure(terminalDiagnostic.c_str()" in socket,
        "closeSocket must feed derived terminal diagnostics back into endpoint resilience state",
    )
    timer_start = socket.find("void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer")
    timer_end = socket.find("void ConnectionSocket::grantProxyHandshakeAdmission", timer_start)
    timer_body = socket[timer_start:timer_end]
    require(
        "proxyHandshakeAdmissionTimerGeneration" in combined
        and "proxyHandshakeAdmissionTimerGeneration = proxyHandshakeAdmissionGeneration;" in timer_body
        and "uint32_t timerGeneration = proxyHandshakeAdmissionTimerGeneration;" in timer_body
        and "timerGeneration != proxyHandshakeAdmissionGeneration || mode == 0" in timer_body
        and "admission_timer_ignored" in timer_body
        and '"admission_timer_ignored": "admission_timer_ignored"' in analyzer,
        "shared MTProxy timer must ignore callbacks from cancelled/replaced handshake generations",
    )
    admission_start = socket.find("bool ConnectionSocket::scheduleProxyHandshakeAdmissionIfNeeded")
    admission_end = socket.find("void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer", admission_start)
    admission_body = socket[admission_start:admission_end]
    require(
        "proxyHandshakeAdmissionQueuePublished" in admission_body
        and "admission_queue_wait" in admission_body
        and "request.queueAlreadyPublished = proxyHandshakeAdmissionQueuePublished" in admission_body
        and "if (decision.publishQueue)" in admission_body,
        "admission queue must publish the UI wait state once and log repeated waits separately",
    )
    close_start = socket.find("void ConnectionSocket::closeSocket")
    close_end = socket.find("void ConnectionSocket::onDisconnected", close_start)
    close_body = socket[close_start:close_end]
    open_connection_start = socket.find("void ConnectionSocket::openConnection(std::string address")
    open_connection_end = socket.find("void ConnectionSocket::openConnectionInternal", open_connection_start)
    open_connection_body = socket[open_connection_start:open_connection_end]
    require(
        "socketCloseNotified" in combined
        and 'setSocketCloseNotified(false, "openConnection")' in open_connection_body
        and "if (socketCloseNotified)" in close_body
        and "close_ignored_already_closed" in close_body
        and '"close_ignored_already_closed": "close_ignored_already_closed"' in analyzer
        and 'setSocketCloseNotified(true, "closeSocket")' in close_body
        and "socket_close_notify_state_change" in socket,
        "closeSocket must be idempotent so one socket failure cannot publish multiple endpoint failures or reconnect backoffs",
    )
    suspend_start = connection.find("void Connection::suspendConnection(bool idle)")
    suspend_end = connection.find("void Connection::onReceivedData", suspend_start)
    suspend_body = connection[suspend_start:suspend_end]
    disconnect_start = connection.find("void Connection::onDisconnectedInternal")
    disconnect_end = connection.find("void Connection::onDisconnected(", disconnect_start)
    disconnect_body = connection[disconnect_start:disconnect_end]
    notify_start = connection.find("void Connection::notifyConnectionClosedOnce")
    notify_end = connection.find("void Connection::onDisconnectedInternal", notify_start)
    notify_body = connection[notify_start:notify_end]
    raw_manager_close = "ConnectionsManager::getInstance(currentDatacenter->instanceNum).onConnectionClosed(this,"
    require(
        "connectionCloseNotified" in connection_header
        and "void notifyConnectionClosedOnce(int32_t reason, const char *source);" in connection_header
        and notify_start != -1
        and "if (connectionCloseNotified)" in notify_body
        and "connection_close_ignored_already_notified" in notify_body
        and '"connection_close_ignored_already_notified": "connection_close_ignored_already_notified"' in analyzer
        and "connectionCloseNotified = true;" in notify_body,
        "Connection must centralize manager close notifications so socket close and suspend cannot both publish one close",
    )
    require(
        "connectionCloseNotified = false;" in connection[connection.find("void Connection::connect()"):connection.find("inline std::string *Connection::getCurrentSecret", connection.find("void Connection::connect()"))]
        and 'notifyConnectionClosedOnce(0, "network_unavailable_connect")' in connection,
        "new connect attempts and no-network exits must use the one-shot Connection close notifier",
    )
    require(
        'notifyConnectionClosedOnce(0, "suspendConnection")' in suspend_body
        and raw_manager_close not in suspend_body,
        "suspendConnection must not directly notify ConnectionsManager after dropConnection; use the one-shot notifier",
    )
    require(
        'notifyConnectionClosedOnce(reason, "onDisconnectedInternal")' in disconnect_body
        and raw_manager_close not in disconnect_body,
        "onDisconnectedInternal must use the one-shot close notifier before reconnect/backoff handling",
    )
    require(
        "!isProxyCloseDiagnosticSuppressed()" in disconnect_body
        and "reconnect_backoff_suppressed" in disconnect_body
        and '"reconnect_backoff_suppressed": "reconnect_backoff_suppressed"' in analyzer,
        "suppressed close diagnostics must not still trigger reconnect_backoff in Connection",
    )
    early_drop_idx = close_body.find('proxyCheckDiagnostic = "dropped_early_after_appdata";')
    suppress_idx = close_body.find("bool suppressProxyCloseDiagnostic = false;")
    suppress_late_drop_idx = close_body.find('proxyCheckDiagnostic == "dropped_after_appdata"', suppress_idx)
    publish_idx = close_body.find("publishProxyConnectionStage(terminalDiagnostic.c_str())")
    require(
        "suppressProxyCloseDiagnostic" in close_body
        and has_phase(close_body, "post_handshake_no_appdata", phase_constants)
        and "!mtproxyFirstTlsFrameSentLogged" in close_body
        and "!mtproxyFirstPlainDataSentLogged" in close_body
        and early_drop_idx >= 0
        and suppress_idx >= 0
        and early_drop_idx < suppress_idx
        and suppress_late_drop_idx >= 0
        and suppress_late_drop_idx < publish_idx
        and 'proxyCheckDiagnostic == "dropped_early_after_appdata"' not in close_body[suppress_idx:publish_idx]
        and "mtproxyFirstTlsDataReceivedLogged || mtproxyFirstPlainDataReceivedLogged" in close_body
        and "proxyCloseDiagnosticSuppressed = true;" in close_body
        and "isProxyCloseDiagnosticSuppressed()" in socket_state_header
        and "close_diagnostic_suppressed" in close_body,
        "closeSocket must publish early post-appdata drops while suppressing only later already-usable post-appdata closes",
    )
    require(
        "!suppressProxyCloseDiagnostic && reason != 0 && isCurrentMtProxyConnection() && !terminalDiagnostic.empty()" in close_body
        and "publishProxyConnectionStage(terminalDiagnostic.c_str())" in close_body
        and "recordMtProxyEndpointFailure(terminalDiagnostic.c_str(), \"closeSocket\")" in close_body,
        "closeSocket must still publish and record real non-suppressed MTProxy close diagnostics",
    )
    require(
        "activeTcpConnects" in socket
        and "releaseMtProxyEndpointTcpConnect" in socket,
        "endpoint resilience state must count active TCP connect attempts and release them",
    )
    require(
        'releaseMtProxyEndpointTcpConnect("socket_connected")' in socket
        and 'releaseMtProxyEndpointTcpConnect("closeSocket")' in socket,
        "active TCP connect gate must release on socket_connected and on closeSocket",
    )
    require(
        'releaseMtProxyEndpointTcpConnect("openConnection_reset")' in socket,
        "new openConnection must release any stale active TCP connect slot before resetting endpoint state",
    )
    require(
        'recordMtProxyEndpointHandshakeOk("server_hello_hmac_ok")' in socket,
        "server_hello_hmac_ok must record handshake boundary without clearing endpoint data-path backoff",
    )
    for marker in [
        'recordMtProxyEndpointDataPathSuccess("first_tls_app_recv")',
        'recordMtProxyEndpointDataPathSuccess("first_mtproxy_packet_recv")',
    ]:
        require(marker in socket, f"endpoint data-path success marker missing: {marker}")
    require(
        "mtProxyEndpointUseCachedHostAddress" in socket and "mtProxyEndpointStoreResolvedAddress" in socket,
        "DNS failures must have a last-good-IP fallback and store path",
    )
    require(
        "resolveInFlightUntil" in endpoint_policy,
        "DNS cache state must record a short in-flight resolve window to suppress duplicate cold resolves",
    )
    sslip_start = endpoint_policy.find("bool MtProxyEndpointPolicy::extractSslipIpv4Address")
    sslip_end = endpoint_policy.find("std::string MtProxyEndpointPolicy::networkEndpointKeyFor", sslip_start)
    sslip_body = endpoint_policy[sslip_start:sslip_end]
    require(
        sslip_start != -1
        and "std::transform" in sslip_body
        and "::tolower" in sslip_body
        and ".sslip.io" in sslip_body,
        "sslip.io fast-path must be case-insensitive so valid domain spelling does not fall through to DNS",
    )
    sslip_call = socket.find("MtProxyEndpointPolicy::extractSslipIpv4Address(*proxyAddress")
    dns_cache_call = socket.find("mtProxyEndpointUseCachedHostAddress(*proxyAddress")
    host_resolve_call = socket.find("requestPendingHostResolve();", dns_cache_call)
    require(
        sslip_call != -1
        and dns_cache_call != -1
        and host_resolve_call != -1
        and sslip_call < dns_cache_call < host_resolve_call,
        "sslip.io fast-path must run before DNS cache lookup and before delegate DNS resolve",
    )
    coalesce_call = socket.find("scheduleMtProxyDnsCoalesceIfNeeded(ipv6)")
    require(
        dns_cache_call < coalesce_call < host_resolve_call,
        "DNS coalescing must run after last-good-IP cache lookup but before delegate DNS resolve",
    )
    require(
        "MtProxyDnsCacheState" in endpoint_policy and "proxyEndpointDnsCache" in endpoint_policy,
        "DNS last-good-IP cache must be stored separately from per-secret/SNI endpoint resilience state",
    )
    require(
        "MtProxyEndpointPolicy::dnsCacheKeyFor" in socket and "dnsCacheKeyFor" in endpoint_policy,
        "DNS cache key must be host/port-scoped instead of secret/SNI-scoped",
    )
    require(
        "mtProxyIsBlockedZeroAddress" in socket
        and "AF_INET6" in socket
        and "closeMtProxyDnsBlockedZeroAddress" in socket
        and "dns_blocked_zero_address" in socket
        and "bool *blockedZeroAddress" in socket
        and "if (blockedZeroAddress != nullptr)" in socket
        and "closeSocket(1, -1)" in socket,
        "native DNS cache hit/store paths must diagnose 0.0.0.0 as dns_blocked_zero_address and stop before TCP connect",
    )
    require(
        "isBlockedZeroAddress" in endpoint_policy
        and "AF_INET6" in endpoint_policy
        and "lastGoodIpv4 = ip" in endpoint_policy
        and "if (isBlockedZeroAddress(ip))" in endpoint_policy,
        "endpoint DNS cache must never store 0.0.0.0 as a last-good IPv4 address",
    )
    require(
        "MtProxyEndpointPolicy::networkEndpointKeyFor" in socket and "networkEndpointKeyFor" in endpoint_policy,
        "pre-TLS endpoint resilience must have a host/port-scoped network key separate from secret/SNI recipe state",
    )
    require(
        "MtProxyEndpointPolicy::admissionKeyFor" in socket
        and "admissionKeyFor" in endpoint_policy
        and "currentMtProxyAdmissionKey" in socket,
        "FakeTLS admission scheduler identity must be a canonical proxy endpoint/SNI key, not rebuilt from mutable Telegram DC fields",
    )
    admission_start = socket.find("bool ConnectionSocket::scheduleProxyHandshakeAdmissionIfNeeded")
    admission_end = socket.find("void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer", admission_start)
    admission_body = socket[admission_start:admission_end]
    require(
        "proxyHandshakeAdmissionKey = currentMtProxyAdmissionKey;" in admission_body
        and "currentAddress + \":\" + std::to_string((unsigned int) currentPort)" not in admission_body,
        "admission scheduling must take its lease key from currentMtProxyAdmissionKey only",
    )
    dns_key_start = endpoint_policy.find("std::string MtProxyEndpointPolicy::dnsCacheKeyFor")
    dns_key_end = endpoint_policy.find("std::string MtProxyEndpointPolicy::stateKeyForPhase", dns_key_start)
    dns_key_body = endpoint_policy[dns_key_start:dns_key_end]
    require(
        ("std::transform" in dns_key_body and "::tolower" in dns_key_body) or "networkEndpointKeyFor(host, port)" in dns_key_body,
        "DNS cache key must lowercase host names so equivalent domains share one last-good-IP entry",
    )
    network_key_start = endpoint_policy.find("std::string MtProxyEndpointPolicy::networkEndpointKeyFor")
    network_key_end = endpoint_policy.find("std::string MtProxyEndpointPolicy::admissionKeyFor", network_key_start)
    network_key_body = endpoint_policy[network_key_start:network_key_end]
    require(
        network_key_start != -1
        and "std::transform" in network_key_body
        and "::tolower" in network_key_body
        and "secretKind" not in network_key_body
        and "domain" not in network_key_body,
        "network endpoint key must be lowercase host/port only; pre-TLS failures must not split by secret/SNI",
    )
    tcp_gate_start = socket.find("bool ConnectionSocket::scheduleMtProxyEndpointTcpConnectGateIfNeeded")
    tcp_gate_end = socket.find("void ConnectionSocket::releaseMtProxyEndpointTcpConnect", tcp_gate_start)
    tcp_gate_body = socket[tcp_gate_start:tcp_gate_end]
    require(
        "currentMtProxyNetworkEndpointKey" in tcp_gate_body
        and "currentMtProxyEndpointKey" not in tcp_gate_body,
        "TCP connect gate must use the host/port network key, not the secret/SNI FakeTLS endpoint key",
    )
    require(
        "MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_REPEAT_MS" in endpoint_policy
        and "proxyEndpointTcpConnectGatePublished" in tcp_gate_body
        and "tcp_connect_gate_wait" in tcp_gate_body
        and "if (!proxyEndpointTcpConnectGatePublished)" in tcp_gate_body,
        "TCP connect gate must publish the UI wait state once and log repeated waits separately",
    )
    tcp_release_start = socket.find("void ConnectionSocket::releaseMtProxyEndpointTcpConnect")
    tcp_release_end = socket.find("bool ConnectionSocket::scheduleMtProxyDnsCoalesceIfNeeded", tcp_release_start)
    tcp_release_body = socket[tcp_release_start:tcp_release_end]
    require(
        "currentMtProxyNetworkEndpointKey" in tcp_release_body
        and "currentMtProxyEndpointKey" not in tcp_release_body,
        "TCP connect gate release must release the same host/port network key it acquired",
    )
    dns_cache_start = socket.find("bool ConnectionSocket::mtProxyEndpointUseCachedHostAddress")
    dns_cache_end = socket.find("MtProxyAdaptivePolicy::RecipeInput ConnectionSocket::currentMtProxyRecipeInput", dns_cache_start)
    dns_cache_body = socket[dns_cache_start:dns_cache_end]
    require(
        "currentMtProxyDnsCacheKey" in dns_cache_body
        and "MtProxyEndpointPolicy::useCachedHostAddress" in dns_cache_body
        and "MtProxyEndpointPolicy::storeResolvedAddress" in dns_cache_body
        and "currentMtProxyEndpointKey" not in dns_cache_body
        and "currentMtProxyRecipeCacheKey" not in dns_cache_body
        and "proxyEndpointResilience" not in dns_cache_body,
        "DNS cache use/store path must not depend on the per-secret/SNI endpoint or recipe key",
    )
    request_start = socket.find("void ConnectionSocket::requestPendingHostResolve")
    request_end = socket.find("void ConnectionSocket::onHostNameResolved", request_start)
    request_body = socket[request_start:request_end]
    no_delegate = request_body.find("manager.delegate == nullptr")
    no_delegate_cache = request_body.find("mtProxyEndpointUseCachedHostAddress(waitingForHostResolve, &cachedIpv6, &blockedZeroAddress)")
    no_delegate_not_started = request_body.find('proxyCheckDiagnostic = "connection_not_started"')
    require(
        no_delegate != -1
        and no_delegate_cache != -1
        and no_delegate_not_started != -1
        and no_delegate < no_delegate_cache < no_delegate_not_started,
        "missing resolver delegate must try last-good-IP cache before publishing connection_not_started, not DNS failure",
    )
    resolved_start = socket.find("void ConnectionSocket::onHostNameResolved")
    resolved_end = socket.find("void ConnectionSocket::openConnectionInternal", resolved_start)
    resolved_body = socket[resolved_start:resolved_end]
    cache_after_delegate_failure = resolved_body.find("mtProxyEndpointUseCachedHostAddress(host, &cachedIpv6, &blockedZeroAddress)")
    host_resolve_failure = resolved_body.find('proxyCheckDiagnostic = "host_resolve_failed"')
    store_resolved = resolved_body.find("mtProxyEndpointStoreResolvedAddress(host, ip)")
    require(
        cache_after_delegate_failure != -1
        and host_resolve_failure != -1
        and cache_after_delegate_failure < host_resolve_failure,
        "delegate DNS failure must try the last-good-IP cache before publishing host_resolve_failed",
    )
    require(
        store_resolved != -1
        and host_resolve_failure != -1
        and host_resolve_failure < store_resolved,
        "delegate DNS success must store the resolved IP only after the failure path has been bypassed",
    )
    require(
        "applyMtProxyPhaseAdaptiveRecipe" in socket,
        "FakeTLS failures must affect the next connection recipe, not only logs",
    )
    recipe_start = probe_coordinator.find("bool MtProxyProbeCoordinator::failureNeedsRecipe")
    recipe_end = probe_coordinator.find("MtProxyAdaptivePolicy::RecipeCursor MtProxyProbeCoordinator::recipeCursorForProbe", recipe_start)
    recipe_body = probe_coordinator[recipe_start:recipe_end]
    require(
        "true_client_hello_timeout" in recipe_body
        and "faketls_server_hello_wait_timeout" in recipe_body
        and "server_closed_after_client_hello" in recipe_body
        and "client_hello_sent_no_server_hello" in recipe_body
        and "server_hello_hmac_mismatch" in recipe_body,
        "phase-adaptive recipe must react only to FakeTLS post-ClientHello handshake failures",
    )
    require(
        'diagnostic == "tcp_not_connected"' in recipe_body
        and 'diagnostic == "tcp_connection_refused"' in recipe_body
        and 'diagnostic == "tcp_connect_timeout"' in recipe_body
        and "return false;" in recipe_body
        and "post_handshake_no_appdata" not in recipe_body
        and "host_resolve_failed" not in recipe_body
        and "host_resolve_timeout" not in recipe_body
        and "mtproxy_packet_sent_no_response" not in recipe_body
        and "dropped_early_after_appdata" not in recipe_body
        and "peer_closed_after_client_hello" not in recipe_body
        and "tcp_connected_no_pong" not in recipe_body,
        "phase-adaptive recipe must not react to DNS/TCP/plain-dd failures where JA4/ClientHello did not help",
    )
    require(
        "MtProxyRecoveryActionKind::PostHandshakeShapingBackoff" in recovery_policy,
        "post-handshake no-appdata must be handled by recovery shaping/backoff, not the recipe cursor ladder",
    )
    failure_start = socket.find("void ConnectionSocket::recordMtProxyEndpointFailure")
    failure_end = socket.find("void ConnectionSocket::recordMtProxyEndpointHandshakeOk", failure_start)
    failure_body = socket[failure_start:failure_end]
    state_key_start = endpoint_policy.find("std::string MtProxyEndpointPolicy::stateKeyForPhase")
    state_key_end = endpoint_policy.find("bool MtProxyEndpointPolicy::failureNeedsCooldown", state_key_start)
    state_key_body = endpoint_policy[state_key_start:state_key_end]
    require(
        "MtProxyEndpointPolicy::recordFailure" in failure_body,
        "endpoint failure recording must route through the phase-aware endpoint-state key helper",
    )
    require(
        '"host_resolve_failed"' in state_key_body
        and '"host_resolve_timeout"' in state_key_body
        and has_phase(state_key_body, "tcp_not_connected", phase_constants)
        and has_phase(state_key_body, "tcp_connection_refused", phase_constants)
        and has_phase(state_key_body, "tcp_connect_timeout", phase_constants)
        and '"tcp_connected_no_pong"' in state_key_body
        and '"mtproxy_packet_sent_no_response"' not in state_key_body
        and '"dropped_early_after_appdata"' in state_key_body
        and "networkEndpointKey" in state_key_body,
        "DNS/TCP failures must use host/port network key, while DD no-response and FakeTLS data-path failures stay exact-config scoped",
    )
    require(
        "proxyEndpointResilience[result.stateKey]" in endpoint_policy
        and "mtProxyProbeStates[probeKey.key]" in probe_coordinator,
        "failure cooldown and FakeTLS recipe must use separate endpoint-policy and probe-coordinator state entries",
    )
    require(
        "currentSecretIsFakeTls" in failure_body
        and "MtProxyProbeCoordinator::failureNeedsRecipe(phase)" in failure_body
        and "mtProxyRecoveryActionAdvancesRecipe(recoveryAction)" in failure_body,
        "recipe level must only advance for FakeTLS connections with cursor-advancing recovery actions, never for dd/legacy MTProxy",
    )
    success_start = socket.find("void ConnectionSocket::recordMtProxyEndpointDataPathSuccess")
    success_end = socket.find("bool ConnectionSocket::mtProxyEndpointUseCachedHostAddress", success_start)
    success_body = socket[success_start:success_end]
    require(
        "MtProxyEndpointPolicy::recordDataPathSuccess" in success_body
        and "resetStateForKey(context.networkEndpointKey" in endpoint_policy
        and "resetStateForKey(context.endpointKey" in endpoint_policy,
        "endpoint data-path success must clear both host/port network cooldown and secret/SNI recipe cooldown",
    )
    invalid_reason_guard = success_body.find('strcmp(reason, "first_tls_app_recv") != 0')
    first_reset = success_body.find("MtProxyEndpointPolicy::recordDataPathSuccess")
    require(
        'reason == nullptr' in success_body
        and 'strcmp(reason, "first_tls_app_recv") != 0' in success_body
        and 'strcmp(reason, "first_mtproxy_packet_recv") != 0' in success_body
        and "endpoint_data_path_success_rejected" in success_body
        and "logTransportInvariant(\"endpoint_data_path_success\", \"invalid_reason\")" in success_body
        and invalid_reason_guard != -1
        and first_reset != -1
        and invalid_reason_guard < first_reset,
        "endpoint data-path success helper must reject non-appdata reasons before clearing endpoint cooldown/backoff",
    )
    adaptive_policy = (ROOT / "TMessagesProj/jni/tgnet/MtProxyAdaptivePolicy.cpp").read_text(encoding="utf-8", errors="replace")
    require(
        "RecipeCursor" in adaptive_policy
        and "buildRecipeCursorLadder" in adaptive_policy
        and "CompatibilityRecipe" in adaptive_policy
        and "nextCursor" in adaptive_policy,
        "phase-adaptive recipe must use the broad cursor ladder before endpoint exhaustion",
    )
    recipe_apply_start = socket.find("void ConnectionSocket::applyMtProxyPhaseAdaptiveRecipe")
    recipe_apply_end = socket.find("void ConnectionSocket::markProxyHandshakeClientHelloSent", recipe_apply_start)
    recipe_apply_body = socket[recipe_apply_start:recipe_apply_end]
    fragment_step = adaptive_policy.find("CLIENT_HELLO_CHROME_MODERN_NO_FRAGMENT")
    legacy_step = adaptive_policy.find("CLIENT_HELLO_LEGACY_NO_GREASE_NO_MODERN_EXTENSIONS")
    parser_step = adaptive_policy.find("PARSER_TOLERATE_EXTRA_RECORDS_BEFORE_SERVER_HELLO")
    optional_no_sni_step = adaptive_policy.find("SNI_OPTIONAL_NO_SNI")
    classic_step = adaptive_policy.find("CLASSIC_STANDARD_INTERMEDIATE")
    require(
        fragment_step != -1
        and legacy_step != -1
        and parser_step != -1
        and optional_no_sni_step != -1
        and classic_step != -1
        and "MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE" in adaptive_policy
        and "MT_PROXY_SERVER_HELLO_PARSER_EXTRA_RECORDS" in adaptive_policy
        and "MT_PROXY_SERVER_HELLO_PARSER_FRAGMENTED_SERVER_HELLO" in adaptive_policy,
        "phase-adaptive recipe must progress through named ClientHello, SNI, parser, and classic buckets",
    )
    require(
        "result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER" in adaptive_policy
        and "result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET" in adaptive_policy,
        "phase-adaptive quiet-start step must make Browser mode quieter after repeated post-ClientHello failures",
    )
    require(
        "MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE" in adaptive_policy
        and "MT_PROXY_TLS_PROFILE_ANDROID_CHROME" in adaptive_policy
        and "MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID" in adaptive_policy,
        "phase-adaptive recipe must switch to another known-compatible TLS profile",
    )
    require(
        "MT_PROXY_TLS_PROFILE_ANDROID_CHROME" in adaptive_policy
        and "MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID" in adaptive_policy,
        "phase-adaptive ClientHello failures must be able to switch between Android Chrome and Firefox Android TLS profiles",
    )
    require(
        "recipeId(const CompatibilityRecipe" in adaptive_policy
        and "familyName" in adaptive_policy
        and "sniVariantName" in adaptive_policy
        and "parserVariantName" in adaptive_policy
        and "classicVariantName" in adaptive_policy,
        "recipe ids must include full cursor identity for broad ladder observability",
    )
    require(
        "input.lastDiagnostic == \"post_handshake_no_appdata\"" in adaptive_policy
        and "result.recordSizingMode = MT_PROXY_RECORD_SIZING_CONSERVATIVE" in adaptive_policy
        and "result.timingMode = MT_PROXY_TIMING_GENTLE" in adaptive_policy
        and "result.startupCoverMode = MT_PROXY_STARTUP_COVER_SOFT" in adaptive_policy,
        "post-handshake no-appdata recipe must escalate data shaping instead of treating it as a ClientHello-only failure",
    )
    require(
        "mtProxyDataAwareIptDelayMs" in data_path_shaper
        and "input.hasPendingTlsFrame || !input.hasOutgoingData" in data_path_shaper
        and "timingInput.hasOutgoingData = outgoingByteStream->hasData();" in socket,
        "post-handshake timing must be data-aware, not idle-thread sleeping",
    )

    for phase in REQUIRED_PHASES:
        require(phase in diagnostics, f"GUI diagnostics must know phase {phase}")
        require(phase in analyzer, f"log analyzer must know phase {phase}")
        require(phase in combined, f"phase {phase} must be present in codebase")

    for string_name in [
        "ProxyStatusEndpointCooldown",
        "ProxyStatusTcpConnectGate",
        "ProxyStatusDnsCoalesceWait",
        "ProxyStatusDnsCacheHit",
        "ProxyStatusDnsCacheStore",
        "ProxyStatusPhaseAdaptiveRecipe",
    ]:
        require(string_name in values, f"English string missing: {string_name}")
        require(string_name in values_ru, f"Russian string missing: {string_name}")

    print("MTProxy endpoint resilience layers guard passed.")


if __name__ == "__main__":
    main()
