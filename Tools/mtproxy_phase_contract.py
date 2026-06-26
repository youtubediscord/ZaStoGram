#!/usr/bin/env python3
from dataclasses import dataclass


PHASE_LIVE = "live"
PHASE_FAILURE = "failure"
PHASE_SUCCESS = "success"
PHASE_NEUTRAL = "neutral"

ENDPOINT_EXACT = "exact"
ENDPOINT_NETWORK = "network"
ENDPOINT_NONE = "none"


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
    MtProxyPhase("phase_adaptive_recipe", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("host_resolve_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("connect_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("socket_connect_start", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("socket_connected", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("client_hello_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("admission_hold_after_client_hello_failure", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("server_hello_hmac_ok", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("on_connected", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_tls_app_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_mtproxy_packet_sent", PHASE_LIVE, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("waiting_tcp", PHASE_LIVE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),

    MtProxyPhase("first_tls_app_recv", PHASE_SUCCESS, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("first_mtproxy_packet_recv", PHASE_SUCCESS, native=True, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK),

    MtProxyPhase("start_failed", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("connection_not_started", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("connecting_timeout", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("admission_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("endpoint_cooldown_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),
    MtProxyPhase("dns_coalesce_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("pre_tcp_gate_admission_overlap", PHASE_FAILURE, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("host_resolve_failed", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("host_resolve_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connect_gate_timeout", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_NETWORK),
    MtProxyPhase("tcp_not_connected", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("tcp_connected_no_pong", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("network_block_suspected", PHASE_FAILURE, native=False, java=True, analyzer=False, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("client_hello_sent_no_server_hello", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("server_hello_hmac_mismatch", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("mtproxy_packet_sent_no_response", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("post_handshake_no_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_EXACT, rotation=True),
    MtProxyPhase("dropped_early_after_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, reconnect_backoff=True, endpoint_key=ENDPOINT_NETWORK, rotation=True),
    MtProxyPhase("dropped_after_appdata", PHASE_FAILURE, native=True, java=True, analyzer=True, endpoint_key=ENDPOINT_EXACT),

    MtProxyPhase("connected_without_socket_connected_marker", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("handshake_ok_no_appdata_sent", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
    MtProxyPhase("shadowed_by_usable_success", PHASE_NEUTRAL, native=False, java=False, analyzer=True, endpoint_key=ENDPOINT_NONE),
)


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
