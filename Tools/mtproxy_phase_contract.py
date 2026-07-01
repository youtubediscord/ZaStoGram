#!/usr/bin/env python3
from dataclasses import dataclass


PHASE_LIVE = "live"
PHASE_FAILURE = "failure"
PHASE_SUCCESS = "success"
PHASE_NEUTRAL = "neutral"

ENDPOINT_EXACT = "exact"
ENDPOINT_NETWORK = "network"
ENDPOINT_NONE = "none"

EVIDENCE_NONE = "none"
EVIDENCE_PRE_TCP_LOCAL_WAIT = "pre_tcp_local_wait"
EVIDENCE_DNS_FAILURE = "dns_failure"
EVIDENCE_TCP_FAILURE = "tcp_failure"
EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO = "no_bytes_after_client_hello"
EVIDENCE_SERVER_BYTES_PARSER_FAILURE = "server_bytes_parser_failure"
EVIDENCE_SERVER_HELLO_HMAC_MISMATCH = "server_hello_hmac_mismatch"
EVIDENCE_POST_HANDSHAKE_NO_APP_DATA = "post_handshake_no_app_data"
EVIDENCE_CONFIG_INVALID_SECRET = "config_invalid_secret"
EVIDENCE_CANCELLED_OR_SHADOWED = "cancelled_or_shadowed"

EVIDENCE_CLASSES = {
    EVIDENCE_NONE,
    EVIDENCE_PRE_TCP_LOCAL_WAIT,
    EVIDENCE_DNS_FAILURE,
    EVIDENCE_TCP_FAILURE,
    EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO,
    EVIDENCE_SERVER_BYTES_PARSER_FAILURE,
    EVIDENCE_SERVER_HELLO_HMAC_MISMATCH,
    EVIDENCE_POST_HANDSHAKE_NO_APP_DATA,
    EVIDENCE_CONFIG_INVALID_SECRET,
    EVIDENCE_CANCELLED_OR_SHADOWED,
}


@dataclass(frozen=True)
class MtProxyPhase:
    name: str
    kind: str
    native: bool
    java: bool
    analyzer: bool
    reconnect_backoff: bool = False
    endpoint_key: str = ENDPOINT_EXACT
    rotation: bool = False


PHASES = (
    MtProxyPhase("ok", PHASE_NEUTRAL, native=False, java=True, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("checking", PHASE_NEUTRAL, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("cancelled", PHASE_NEUTRAL, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("unknown_fail", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),

    MtProxyPhase("admission_queue", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("endpoint_cooldown", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("tcp_connect_gate", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("dns_coalesce_wait", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("dns_cache_hit", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("dns_cache_store", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("mtproxy_probe_wait", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("phase_adaptive_recipe", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("secret_domain_sanitized", PHASE_LIVE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("host_resolve_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("connect_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("socket_connect_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("socket_connected", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("client_hello_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("admission_hold_after_client_hello_failure", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("server_hello_hmac_ok", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("on_connected", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_tls_app_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_mtproxy_packet_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("waiting_tcp", PHASE_LIVE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),

    MtProxyPhase("first_tls_app_recv", PHASE_SUCCESS, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_mtproxy_packet_recv", PHASE_SUCCESS, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),

    MtProxyPhase("start_failed", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("connection_not_started", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("connecting_timeout", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("admission_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("endpoint_cooldown_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("mtproxy_probe_wait_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("dns_coalesce_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("dns_negative_cache_hit", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("dns_blocked_zero_address", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("pre_tcp_gate_admission_overlap", PHASE_FAILURE, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("tcp_budget_stolen_by_pre_tcp_wait", PHASE_FAILURE, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("dns_budget_stolen_by_pre_tcp_wait", PHASE_FAILURE, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("host_resolve_failed", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("host_resolve_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connect_gate_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("tcp_not_connected", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connection_refused", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connect_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connected_no_pong", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("network_block_suspected", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("secret_parse_invalid_domain_control_char", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("secret_parse_invalid_domain", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("true_client_hello_timeout", PHASE_FAILURE, native=False, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("faketls_server_hello_wait_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("server_closed_after_client_hello", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("client_hello_sent_no_server_hello", PHASE_FAILURE, native=False, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("tls_alert_after_client_hello", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("short_tls_response_after_client_hello", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("unrecognized_response_after_client_hello", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("unrecognized_tls_response_after_client_hello", PHASE_FAILURE, native=False, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("server_hello_hmac_mismatch", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("background_handshake_aborted", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("handshake_profiles_exhausted", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("mtproxy_packet_sent_no_response", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("post_handshake_no_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("dropped_early_after_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("dropped_after_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),

    MtProxyPhase("connected_without_socket_connected_marker", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("handshake_ok_no_appdata_sent", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("shadowed_by_usable_success", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("shadowed_socket_failure", PHASE_NEUTRAL, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("ignored_cancelled_generation", PHASE_NEUTRAL, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("reconnect_backoff_suppressed", PHASE_NEUTRAL, native=True, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
)

PHASE_EVIDENCE = {
    "connection_not_started": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "admission_timeout": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "endpoint_cooldown_timeout": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "mtproxy_probe_wait_timeout": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "dns_coalesce_timeout": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "tcp_connect_gate_timeout": EVIDENCE_PRE_TCP_LOCAL_WAIT,
    "dns_negative_cache_hit": EVIDENCE_DNS_FAILURE,
    "dns_blocked_zero_address": EVIDENCE_DNS_FAILURE,
    "host_resolve_failed": EVIDENCE_DNS_FAILURE,
    "host_resolve_timeout": EVIDENCE_DNS_FAILURE,
    "tcp_not_connected": EVIDENCE_TCP_FAILURE,
    "tcp_connection_refused": EVIDENCE_TCP_FAILURE,
    "tcp_connect_timeout": EVIDENCE_TCP_FAILURE,
    "tcp_connected_no_pong": EVIDENCE_TCP_FAILURE,
    "faketls_server_hello_wait_timeout": EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO,
    "true_client_hello_timeout": EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO,
    "client_hello_sent_no_server_hello": EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO,
    "tls_alert_after_client_hello": EVIDENCE_SERVER_BYTES_PARSER_FAILURE,
    "short_tls_response_after_client_hello": EVIDENCE_SERVER_BYTES_PARSER_FAILURE,
    "unrecognized_response_after_client_hello": EVIDENCE_SERVER_BYTES_PARSER_FAILURE,
    "unrecognized_tls_response_after_client_hello": EVIDENCE_SERVER_BYTES_PARSER_FAILURE,
    "server_hello_hmac_mismatch": EVIDENCE_SERVER_HELLO_HMAC_MISMATCH,
    "post_handshake_no_appdata": EVIDENCE_POST_HANDSHAKE_NO_APP_DATA,
    "mtproxy_packet_sent_no_response": EVIDENCE_POST_HANDSHAKE_NO_APP_DATA,
    "dropped_early_after_appdata": EVIDENCE_POST_HANDSHAKE_NO_APP_DATA,
    "dropped_after_appdata": EVIDENCE_POST_HANDSHAKE_NO_APP_DATA,
    "secret_parse_invalid_domain_control_char": EVIDENCE_CONFIG_INVALID_SECRET,
    "secret_parse_invalid_domain": EVIDENCE_CONFIG_INVALID_SECRET,
    "background_handshake_aborted": EVIDENCE_CANCELLED_OR_SHADOWED,
    "shadowed_socket_failure": EVIDENCE_CANCELLED_OR_SHADOWED,
    "ignored_cancelled_generation": EVIDENCE_CANCELLED_OR_SHADOWED,
}


def _validate_contract() -> None:
    names = [phase.name for phase in PHASES]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise RuntimeError("duplicate MTProxy phase names: " + ", ".join(duplicates))
    for phase in PHASES:
        if phase.kind not in {PHASE_LIVE, PHASE_FAILURE, PHASE_SUCCESS, PHASE_NEUTRAL}:
            raise RuntimeError(f"invalid phase kind for {phase.name}: {phase.kind}")
        if phase.endpoint_key not in {ENDPOINT_EXACT, ENDPOINT_NETWORK, ENDPOINT_NONE}:
            raise RuntimeError(f"invalid endpoint key mode for {phase.name}: {phase.endpoint_key}")
    if not set(PHASE_EVIDENCE.values()) <= EVIDENCE_CLASSES:
        raise RuntimeError("phase evidence mapping contains unknown evidence classes")


def phases() -> tuple[MtProxyPhase, ...]:
    return PHASES


def java_phase_names() -> set[str]:
    return {phase.name for phase in PHASES if phase.java}


def native_phase_names() -> set[str]:
    return {phase.name for phase in PHASES if phase.native}


def analyzer_phase_names() -> set[str]:
    return {phase.name for phase in PHASES if phase.analyzer}


def analyzer_failure_phases() -> set[str]:
    return {phase.name for phase in PHASES if phase.analyzer and phase.kind == PHASE_FAILURE}


def evidence_classes() -> set[str]:
    return set(EVIDENCE_CLASSES)


def evidence_for_phase(phase: str, response_bytes: int = 0) -> str:
    if phase == "server_closed_after_client_hello":
        return (
            EVIDENCE_SERVER_BYTES_PARSER_FAILURE
            if response_bytes > 0
            else EVIDENCE_NO_BYTES_AFTER_CLIENT_HELLO
        )
    return PHASE_EVIDENCE.get(phase, EVIDENCE_NONE)


def java_visible_live_phases() -> set[str]:
    return {phase.name for phase in PHASES if phase.java and phase.kind in {PHASE_LIVE, PHASE_SUCCESS}}


def java_success_phases() -> set[str]:
    return {phase.name for phase in PHASES if phase.java and phase.kind == PHASE_SUCCESS}


def reconnect_backoff_phases() -> set[str]:
    return {phase.name for phase in PHASES if phase.reconnect_backoff}


def endpoint_key_phases(endpoint_key: str) -> set[str]:
    return {
        phase.name
        for phase in PHASES
        if phase.java and phase.kind == PHASE_FAILURE and phase.endpoint_key == endpoint_key
    }


def rotation_phases() -> set[str]:
    return {phase.name for phase in PHASES if phase.rotation}


_validate_contract()
