#!/usr/bin/env python3
"""Verify live MTProxy runtime log evidence after an APK/logcat capture.

This is intentionally stricter than the human-facing analyzer. It answers the
post-build question from the transport-state hardening work: did the live log
actually contain the new state fields and the split endpoint-success markers?
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from mtproxy_phase_contract import evidence_classes


REASON_RE = re.compile(r"(?<![A-Za-z0-9_])reason=([^ ]+)")
CONNECTION_RE = re.compile(r"connection\((0x[0-9a-fA-F]+)\)")
LOG_TIME_RE = re.compile(r"\b(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})\b")
PROXY_CONTROL_RE = re.compile(r"proxy_control decision=([^ ]+)")
FIELD_RE_TEMPLATE = r"(?<![A-Za-z0-9_]){}=([^ ]+)"
EMPTY_DOH_NAME_RE = re.compile(r"https://[^ ]+/(?:resolve|dns-query)\?name=(?:&|$)")
DISCONNECT_REQUIRED_FIELDS = (
    "transport_state=",
    "epoll_registered=",
    "admission_active=",
    "tcp_gate_active=",
)
ALLOWED_DATA_PATH_REASONS = {"first_tls_app_recv", "first_mtproxy_packet_recv"}
FAILURE_EVIDENCE_CLASSES = evidence_classes()
ACTIVE_SOCKET_ORIGINS = {"active_socket", "active_proxy"}
RECIPE_FAILURE_MARKERS = ("mtproxy_startup recipe_failed", "mtproxy_startup recipe_exhausted")
USABLE_SUCCESS_PROXY_PHASES = {"first_tls_app_recv", "first_mtproxy_packet_recv"}
NATIVE_SOCKET_OBSERVATION_FACADE_PHASES = {
    "recipe_failed",
    "handshake_profiles_exhausted",
    "secret_parse_invalid_domain_control_char",
    "secret_parse_invalid_domain",
    "dns_blocked_zero_address",
    "post_handshake_no_appdata",
    "first_tls_app_recv",
    "first_mtproxy_packet_recv",
}
VISIBLE_SUCCESS_HOLD_MS = 45 * 1000
DNS_VISIBLE_DELAY_MS = 800
DNS_VISIBLE_TELEMETRY_PHASES = {"host_resolve_start", "dns_coalesce_wait"}
LIVE_VISIBLE_OVERWRITE_PHASES = {
    "dns_cache_hit",
    "dns_cache_store",
    "dns_coalesce_wait",
    "mtproxy_probe_wait",
    "connect_start",
    "socket_connect_start",
    "tcp_connect_gate",
    "socket_connected",
    "client_hello_sent",
    "server_hello_hmac_ok",
    "on_connected",
    "first_tls_app_sent",
    "admission_queue",
    "endpoint_cooldown",
    "host_resolve_start",
}
FRESH_USABLE_FAILURE_OVERWRITE_PHASES = {
    "tcp_not_connected",
    "tcp_connection_refused",
    "tcp_connect_timeout",
    "host_resolve_failed",
    "host_resolve_timeout",
    "dns_blocked_zero_address",
    "tcp_connected_no_pong",
    "network_block_suspected",
    "true_client_hello_timeout",
    "faketls_server_hello_wait_timeout",
    "server_closed_after_client_hello",
    "client_hello_sent_no_server_hello",
    "tls_alert_after_client_hello",
    "short_tls_response_after_client_hello",
    "unrecognized_response_after_client_hello",
    "unrecognized_tls_response_after_client_hello",
    "server_hello_hmac_mismatch",
    "background_handshake_aborted",
    "handshake_profiles_exhausted",
    "unsupported_for_current_client",
    "mtproxy_packet_sent_no_response",
    "post_handshake_no_appdata",
    "dropped_early_after_appdata",
    "dropped_after_appdata",
    "connecting_timeout",
}
POST_SUCCESS_BREAKTHROUGH_FAILURE_PHASES = {
    "tcp_connected_no_pong",
    "mtproxy_packet_sent_no_response",
    "post_handshake_no_appdata",
    "dropped_early_after_appdata",
}
USABLE_HOLD_DECISIONS = {
    "held_live_by_usable_success",
    "held_live_by_current_proxy_usable",
    "held_by_usable_success",
    "held_by_current_proxy_usable",
    "shadowed_by_usable_success",
    "shadowed_socket_failure",
}
TERMINAL_ONE_SHOT_PHASES = {
    "secret_parse_invalid_domain_control_char",
    "secret_parse_invalid_domain",
}
PUNITIVE_ROTATION_PHASES = {
    "tcp_not_connected",
    "tcp_connection_refused",
    "tcp_connect_timeout",
    "host_resolve_failed",
    "host_resolve_timeout",
    "tcp_connected_no_pong",
    "handshake_profiles_exhausted",
    "mtproxy_packet_sent_no_response",
    "post_handshake_no_appdata",
    "dropped_early_after_appdata",
}
PRE_SOCKET_TCP_FAILURE_PHASES = {
    "tcp_not_connected",
    "tcp_connection_refused",
    "tcp_connect_timeout",
}
ROTATION_HYSTERESIS_WINDOW_MS = 30 * 1000
ROTATION_FAILURES_TO_TRIGGER = 2
WARMUP_UPLOAD_GET_FILE_LIMIT = 3
WARMUP_TCP_CONNECT_GATE_LIMIT = 5
DNS_OUTAGE_HOLD_MS = 60 * 1000
DNS_OUTAGE_PROVIDERS = {"system", "google_json_doh", "cloudflare_json_doh"}
ROTATED_AWAY_HOLD_MS = 45 * 1000
ROTATED_AWAY_ALLOWED_DECISIONS = {"cancel_endpoint_attempts", "ignored_cancelled_generation", "ignored_rotated_away", "ignored_stale_endpoint"}
STANDARD_HMAC_PARSER = "standard_hmac_parser"
NO_BYTE_AFTER_CLIENT_HELLO_PHASES = {
    "true_client_hello_timeout",
    "faketls_server_hello_wait_timeout",
    "server_closed_after_client_hello",
    "client_hello_sent_no_server_hello",
}


def resolve_markers_path(path: Path) -> Path:
    if path.is_dir():
        marker_path = path / "mtproxy_markers.txt"
    else:
        marker_path = path
    if not marker_path.exists():
        raise SystemExit(f"markers file not found: {marker_path}")
    return marker_path


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def line_reason(line: str) -> str:
    match = REASON_RE.search(line)
    return match.group(1) if match else ""


def line_connection(line: str) -> str:
    match = CONNECTION_RE.search(line)
    return match.group(1) if match else ""


def line_time_ms(line: str) -> int | None:
    match = LOG_TIME_RE.search(line)
    if not match:
        return None
    month, day, hour, minute, second, millis = (int(part) for part in match.groups())
    return (((month * 31 + day) * 24 + hour) * 60 * 60 + minute * 60 + second) * 1000 + millis


def line_field(line: str, name: str) -> str:
    match = re.search(FIELD_RE_TEMPLATE.format(re.escape(name)), line)
    return match.group(1) if match else ""


def line_int_field(line: str, name: str) -> int:
    try:
        return int(line_field(line, name))
    except ValueError:
        return 0


def proxy_control_decision(line: str) -> str:
    match = PROXY_CONTROL_RE.search(line)
    return match.group(1) if match else ""


def endpoint_from_key(key: str) -> str:
    if not key:
        return ""
    prefix, separator, tail = key.rpartition(":")
    if separator and prefix and not tail.isdigit():
        return prefix
    return key


def line_endpoint(line: str, connection_endpoints: dict[str, str]) -> str:
    endpoint = line_field(line, "endpoint")
    if endpoint:
        return endpoint
    key = line_field(line, "key") or line_field(line, "network_key")
    if key:
        return endpoint_from_key(key)
    connection = line_connection(line)
    return connection_endpoints.get(connection, "")


def verify_failure_evidence(lines: list[str]) -> list[str]:
    failures: list[str] = []
    for line in lines:
        evidence = line_field(line, "evidence")
        if evidence and evidence not in FAILURE_EVIDENCE_CLASSES:
            failures.append(f"unknown MTProxy failure evidence class: {line}")
        if not any(marker in line for marker in RECIPE_FAILURE_MARKERS):
            continue
        if not evidence:
            failures.append(f"recipe failure marker missing evidence= field: {line}")
        if "response_bytes=" not in line:
            failures.append(f"recipe failure marker missing response_bytes= field: {line}")
    return failures


def same_proxy_endpoint(left: str, right: str) -> bool:
    return bool(left and right and (left == right or left.startswith(right) or right.startswith(left)))


def same_proxy_probe(left: str, right: str) -> bool:
    return not left or not right or left == right


def endpoint_host(endpoint: str) -> str:
    if not endpoint:
        return ""
    return endpoint.split(":", 1)[0].lower()


def has_prior_connection_marker(lines: list[str], index: int, connection: str, marker: str) -> bool:
    for candidate in lines[:index]:
        if marker not in candidate:
            continue
        if connection and line_connection(candidate) != connection:
            continue
        return True
    return False


def line_is_post_success_shadow(line: str) -> bool:
    decision = proxy_control_decision(line)
    phase = line_field(line, "phase")
    if decision == "post_success_shadow_budget":
        return True
    if decision == "shadowed_by_usable_success" and phase in POST_SUCCESS_BREAKTHROUGH_FAILURE_PHASES:
        return True
    if "shadowed_socket_failure" in line:
        return True
    if "endpoint_failure_shadowed_by_success" in line and phase in POST_SUCCESS_BREAKTHROUGH_FAILURE_PHASES:
        return True
    return False


def has_prior_post_success_shadow(
    lines: list[str],
    current_line: str,
    endpoint: str,
    success_time: int | None,
    current_time: int | None,
) -> bool:
    for candidate in lines:
        if candidate == current_line:
            break
        if not line_is_post_success_shadow(candidate):
            continue
        candidate_endpoint = line_endpoint(candidate, {})
        if endpoint and not candidate_endpoint:
            continue
        if endpoint and candidate_endpoint and not same_proxy_endpoint(candidate_endpoint, endpoint):
            continue
        candidate_time = line_time_ms(candidate)
        if success_time is not None and candidate_time is not None and candidate_time < success_time:
            continue
        if current_time is not None and candidate_time is not None and candidate_time > current_time:
            continue
        return True
    return False


def verify_visible_success_hold(lines: list[str]) -> list[str]:
    failures: list[str] = []
    usable_successes: list[tuple[int | None, str, str]] = []
    for line in lines:
        decision = proxy_control_decision(line)
        if not decision:
            continue
        phase = line_field(line, "phase")
        endpoint = line_field(line, "endpoint")
        origin = line_field(line, "origin")
        if decision in {"visible_usable_success", "visible_only"} and origin and origin not in ACTIVE_SOCKET_ORIGINS:
            failures.append(f"non-active origin mirrored as active visible status: {line}")
            continue
        if decision == "visible_usable_success" and phase in USABLE_SUCCESS_PROXY_PHASES:
            usable_successes.append((line_time_ms(line), endpoint, line))
            continue
        if decision == "visible_only" and line_field(line, "source") == "proxy_check":
            current_time = line_time_ms(line)
            for success_time, _, success_line in usable_successes:
                if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                    continue
                failures.append(
                    "proxy-check/candidate event mirrored as active visible status after usable success: "
                    f"{line} after {success_line}"
                )
                break
        if decision != "visible_only" or phase not in LIVE_VISIBLE_OVERWRITE_PHASES | FRESH_USABLE_FAILURE_OVERWRITE_PHASES:
            continue
        current_time = line_time_ms(line)
        for success_time, success_endpoint, success_line in usable_successes:
            if not same_proxy_endpoint(success_endpoint, endpoint):
                continue
            if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                continue
            if phase in FRESH_USABLE_FAILURE_OVERWRITE_PHASES:
                failures.append(
                    "visible usable success overwritten by failure visible_only within 45s: "
                    f"{line} after {success_line}"
                )
                break
            failures.append(
                "visible usable success overwritten by live visible_only within 45s: "
                f"{line} after {success_line}"
            )
            break
    return failures


def verify_one_shot_terminal(lines: list[str]) -> list[str]:
    failures: list[str] = []
    terminal_seen: list[tuple[int | None, str, str, str, str]] = []
    terminal_quarantine_seen: set[tuple[str, str, str]] = set()
    cancellation_seen: set[tuple[str, str, str]] = set()
    for line in lines:
        decision = proxy_control_decision(line)
        phase = line_field(line, "phase")
        endpoint = line_field(line, "endpoint")
        probeKey = line_field(line, "probe")
        if phase in TERMINAL_ONE_SHOT_PHASES:
            terminal_seen.append((line_time_ms(line), phase, endpoint, probeKey, line))
        if decision == "held_by_failure_hysteresis" and phase in TERMINAL_ONE_SHOT_PHASES:
            failures.append(f"one-shot terminal phase must not wait in failure hysteresis: {line}")
        if "proxy_rotation decision=waiting_hysteresis" in line and phase in TERMINAL_ONE_SHOT_PHASES:
            failures.append(f"one-shot terminal phase must not wait in rotation hysteresis: {line}")
        if decision == "backoff" and phase in TERMINAL_ONE_SHOT_PHASES and "rotation_allowed=false" in line:
            failures.append(f"one-shot terminal backoff must allow immediate quarantine: {line}")
        if decision == "terminal_quarantine" and phase in TERMINAL_ONE_SHOT_PHASES:
            terminal_quarantine_seen.add((phase, endpoint, probeKey))
        if "cancel_endpoint_attempts" in line and phase in TERMINAL_ONE_SHOT_PHASES:
            cancellation_seen.add((phase, endpoint, probeKey))

    for _, phase, endpoint, probeKey, line in terminal_seen:
        if not endpoint:
            continue
        if not any(
            item_phase == phase
            and same_proxy_endpoint(item_endpoint, endpoint)
            and same_proxy_probe(item_probeKey, probeKey)
            for item_phase, item_endpoint, item_probeKey in terminal_quarantine_seen
        ):
            failures.append(f"one-shot terminal phase missing terminal_quarantine: {line}")
        if not any(
            item_phase == phase
            and same_proxy_endpoint(item_endpoint, endpoint)
            and same_proxy_probe(item_probeKey, probeKey)
            for item_phase, item_endpoint, item_probeKey in cancellation_seen
        ):
            failures.append(f"one-shot terminal phase missing cancel_endpoint_attempts: {line}")
    return failures


def verify_server_hello_diagnostics(lines: list[str]) -> list[str]:
    failures: list[str] = []
    client_hello_connections: set[str] = set()
    eof_after_client_hello: dict[str, str] = {}
    for line in lines:
        connection = line_connection(line)
        if not connection:
            continue
        if "client_hello_sent" in line:
            client_hello_connections.add(connection)
            continue
        if "recv_eof" in line and "proxy_state=11" in line and connection in client_hello_connections:
            eof_after_client_hello[connection] = line
            continue
        if "close_diagnostic" not in line or "phase=true_client_hello_timeout" not in line:
            continue
        if connection not in eof_after_client_hello:
            continue
        failures.append(
            "EOF after ClientHello must be reported as server_closed_after_client_hello, "
            f"not true_client_hello_timeout: {line} after {eof_after_client_hello[connection]}"
        )
    return failures


def verify_shadowed_socket_backoff(lines: list[str]) -> list[str]:
    failures: list[str] = []
    usable_successes: list[tuple[int | None, str, str]] = []
    shadowed_post_handshake = False
    for line in lines:
        decision = proxy_control_decision(line)
        phase = line_field(line, "phase")
        endpoint = line_field(line, "endpoint")
        if decision == "visible_usable_success" and phase in USABLE_SUCCESS_PROXY_PHASES:
            usable_successes.append((line_time_ms(line), endpoint, line))
            continue
        if "shadowed_socket_failure" in line and "phase=post_handshake_no_appdata" in line:
            shadowed_post_handshake = True
            continue
        if "reconnect_backoff_suppressed" in line and "phase=post_handshake_no_appdata" in line:
            shadowed_post_handshake = True
            continue
        if "reconnect_backoff" not in line or "phase=post_handshake_no_appdata" not in line:
            continue
        current_time = line_time_ms(line)
        for success_time, success_endpoint, success_line in usable_successes:
            if endpoint and success_endpoint and not same_proxy_endpoint(success_endpoint, endpoint):
                continue
            if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                continue
            if not shadowed_post_handshake:
                failures.append(
                    "post_handshake_no_appdata created reconnect_backoff after fresh usable success; "
                    f"use shadowed_socket_failure/reconnect_backoff_suppressed: {line} after {success_line}"
                )
            break
    return failures


def verify_usable_hold_anchor(lines: list[str]) -> list[str]:
    failures: list[str] = []
    for line in lines:
        decision = proxy_control_decision(line)
        if decision not in USABLE_HOLD_DECISIONS:
            continue
        held_by = line_field(line, "held_by")
        if held_by not in FRESH_USABLE_FAILURE_OVERWRITE_PHASES:
            continue
        failures.append(f"fresh usable hold anchored to failure phase: {line}")
    return failures


def verify_dns_visible_debounce(lines: list[str]) -> list[str]:
    failures: list[str] = []
    telemetry: list[tuple[int | None, str, str, str]] = []
    for line in lines:
        decision = proxy_control_decision(line)
        if not decision:
            continue
        phase = line_field(line, "phase")
        endpoint = line_field(line, "endpoint")
        current_time = line_time_ms(line)
        if decision == "visible_only" and phase in DNS_VISIBLE_TELEMETRY_PHASES:
            failures.append(f"short DNS telemetry mirrored as visible; use telemetry_only/visible_delayed_dns: {line}")
            continue
        if decision == "telemetry_only" and phase in DNS_VISIBLE_TELEMETRY_PHASES:
            telemetry.append((current_time, endpoint, phase, line))
            continue
        if decision != "visible_delayed_dns":
            continue
        if phase not in DNS_VISIBLE_TELEMETRY_PHASES:
            failures.append(f"visible_delayed_dns used for non-DNS phase: {line}")
            continue
        matching = [
            item
            for item in telemetry
            if item[2] == phase and same_proxy_endpoint(item[1], endpoint)
        ]
        if not matching:
            failures.append(f"visible_delayed_dns without prior telemetry_only: {line}")
            continue
        start_time, _, _, start_line = matching[-1]
        if start_time is not None and current_time is not None and current_time - start_time < DNS_VISIBLE_DELAY_MS:
            failures.append(f"visible_delayed_dns before {DNS_VISIBLE_DELAY_MS}ms debounce: {line} after {start_line}")
    return failures


def verify_rotation_hysteresis(lines: list[str]) -> list[str]:
    failures: list[str] = []
    usable_successes: list[tuple[int | None, str, str]] = []
    for line in lines:
        if proxy_control_decision(line) == "visible_usable_success" and line_field(line, "phase") in USABLE_SUCCESS_PROXY_PHASES:
            usable_successes.append((line_time_ms(line), line_field(line, "endpoint"), line))
            continue
        if "proxy_rotation decision=trigger" in line:
            origin = line_field(line, "origin")
            if origin and origin not in ACTIVE_SOCKET_ORIGINS:
                failures.append(f"proxy_rotation trigger from non-active origin: {line}")
        if "proxy_rotation decision=trigger_terminal_exact" in line:
            phase = line_field(line, "phase")
            if phase not in TERMINAL_ONE_SHOT_PHASES:
                failures.append(f"terminal exact rotation trigger from non-terminal phase: {line}")
            continue
        if "proxy_rotation decision=trigger" not in line:
            continue
        phase = line_field(line, "phase")
        endpoint = line_field(line, "endpoint")
        current_time = line_time_ms(line)
        if phase not in PUNITIVE_ROTATION_PHASES:
            failures.append(f"proxy_rotation trigger from non-punitive phase: {line}")
            continue
        count_text = line_field(line, "count")
        try:
            count = int(count_text)
        except ValueError:
            count = 0
        if count < ROTATION_FAILURES_TO_TRIGGER:
            failures.append(f"proxy_rotation trigger before hysteresis count reached {ROTATION_FAILURES_TO_TRIGGER}: {line}")
        for success_time, success_endpoint, success_line in usable_successes:
            if not same_proxy_endpoint(success_endpoint, endpoint):
                continue
            if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                continue
            if phase in POST_SUCCESS_BREAKTHROUGH_FAILURE_PHASES and has_prior_post_success_shadow(lines, line, endpoint, success_time, current_time):
                continue
            failures.append(f"proxy_rotation trigger held by fresh usable success: {line} after {success_line}")
            break
        previous_punitive = False
        for candidate in lines:
            if candidate == line:
                break
            if "proxy_rotation decision=waiting_hysteresis" not in candidate:
                continue
            if line_field(candidate, "phase") != phase or not same_proxy_endpoint(line_field(candidate, "endpoint"), endpoint):
                continue
            candidate_time = line_time_ms(candidate)
            if candidate_time is not None and current_time is not None and current_time - candidate_time > ROTATION_HYSTERESIS_WINDOW_MS:
                continue
            previous_punitive = True
        if not previous_punitive:
            failures.append(f"proxy_rotation trigger without a prior punitive waiting_hysteresis inside 30s: {line}")
    return failures


def verify_dns_outage_rotation_hold(lines: list[str]) -> list[str]:
    failures: list[str] = []
    provider_failures: dict[str, tuple[int | None, set[str]]] = {}
    for line in lines:
        if "dns_resolver provider=" in line and ("result=success" in line or "result=stale" in line or "result=stale_dns_used" in line):
            host = line_field(line, "host").lower()
            if host:
                provider_failures.pop(host, None)
            continue
        if "dns_resolver fallback provider=" in line:
            provider = line_field(line, "provider")
            host = line_field(line, "host").lower()
            if provider in DNS_OUTAGE_PROVIDERS and host:
                failed_at, providers = provider_failures.get(host, (line_time_ms(line), set()))
                providers.add(provider)
                provider_failures[host] = (failed_at, providers)
            continue
        if "proxy_rotation decision=trigger" not in line or line_field(line, "phase") != "host_resolve_failed":
            continue
        endpoint = line_field(line, "endpoint")
        host = endpoint_host(endpoint)
        failed_at, providers = provider_failures.get(host, (None, set()))
        if not DNS_OUTAGE_PROVIDERS.issubset(providers):
            continue
        current_time = line_time_ms(line)
        if failed_at is not None and current_time is not None and current_time - failed_at > DNS_OUTAGE_HOLD_MS:
            continue
        failures.append(f"proxy_rotation trigger during DNS outage: {line}")
    return failures


def verify_rotated_away_endpoint_hold(lines: list[str]) -> list[str]:
    failures: list[str] = []
    rotation_triggers: list[tuple[int | None, str, str]] = []
    for line in lines:
        if "proxy_rotation decision=trigger" in line:
            rotation_triggers.append((line_time_ms(line), line_field(line, "endpoint"), line))
            continue
        decision = proxy_control_decision(line)
        if decision == "terminal_quarantine":
            rotation_triggers.append((line_time_ms(line), line_field(line, "endpoint"), line))
            continue
        if not decision:
            continue
        endpoint = line_field(line, "endpoint")
        if not endpoint:
            continue
        current_time = line_time_ms(line)
        for trigger_time, trigger_endpoint, trigger_line in rotation_triggers:
            if not same_proxy_endpoint(trigger_endpoint, endpoint):
                continue
            if trigger_time is not None and current_time is not None and current_time - trigger_time > ROTATED_AWAY_HOLD_MS:
                continue
            if decision in ROTATED_AWAY_ALLOWED_DECISIONS:
                break
            failures.append(
                "rotated-away endpoint telemetry accepted after rotation trigger: "
                f"{line} after {trigger_line}"
            )
            break
    return failures


def verify_dns_resolver_logs(lines: list[str]) -> list[str]:
    failures: list[str] = []
    for line in lines:
        if EMPTY_DOH_NAME_RE.search(line):
            failures.append(f"dns resolver must not build DoH URL with empty name=: {line}")
        if "dns_resolver fallback provider=" in line:
            continue
        if "FileNotFoundException" in line and "/resolve" in line and ("E/tmessages" in line or "FileLog.e" in line):
            failures.append(f"dns resolver must not log expected DoH fallback as E/tmessages /resolve: {line}")
        if "www.google.com/resolve" in line:
            failures.append(f"dns resolver must not use legacy www.google.com/resolve endpoint: {line}")
        if "Host: dns.google.com" in line or 'Host", "dns.google.com' in line:
            failures.append(f"dns resolver must not spoof Host header for DoH: {line}")
    return failures


def verify_startup_warmup_fanout(lines: list[str]) -> list[str]:
    failures: list[str] = []
    first_usable_index: int | None = None
    for index, line in enumerate(lines):
        if "first_tls_app_recv" in line or "first_mtproxy_packet_recv" in line:
            first_usable_index = index
            break
    if first_usable_index is None:
        return failures

    before_usable = lines[:first_usable_index]
    repeated_delay_lines: dict[str, list[str]] = {}
    for line in before_usable:
        lower_line = line.lower()
        if "proxy_warmup state=" not in lower_line or "decision=delay" not in lower_line or "delay=1500" not in lower_line:
            continue
        if "class=stories_prefetch" not in lower_line and "class=sticker_prefetch" not in lower_line:
            continue
        request_class = line_field(lower_line, "class") or "unknown"
        account = line_field(lower_line, "account") or "unknown"
        endpoint = line_field(lower_line, "endpoint") or "none"
        repeated_delay_lines.setdefault(f"{account}:{request_class}:{endpoint}", []).append(line)
    for key, matching_lines in repeated_delay_lines.items():
        if len(matching_lines) > 1:
            failures.append(
                "proxy_warmup prefetch delays must be bucketed before first usable success: "
                f"key={key} count={len(matching_lines)} first={matching_lines[0]}"
            )

    upload_get_file_lines = [line for line in before_usable if "upload_getFile" in line]
    if len(upload_get_file_lines) > WARMUP_UPLOAD_GET_FILE_LIMIT:
        failures.append(
            "startup fanout before first usable success: "
            f"count(upload_getFile) > 3 actual={len(upload_get_file_lines)} first={upload_get_file_lines[0]}"
        )

    tcp_gate_lines = [line for line in before_usable if "tcp_connect_gate" in line]
    if len(tcp_gate_lines) > WARMUP_TCP_CONNECT_GATE_LIMIT:
        failures.append(
            "tcp_connect_gate before first usable success: "
            f"count(tcp_connect_gate) > 5 actual={len(tcp_gate_lines)} first={tcp_gate_lines[0]}"
        )

    story_network_lines: list[str] = []
    for line in before_usable:
        lower_line = line.lower()
        if "stor" not in lower_line:
            continue
        if "upload_getfile" in lower_line or "create load operation" in lower_line:
            story_network_lines.append(line)
            continue
        if "proxy_warmup" in lower_line and "class=stories_prefetch" in lower_line and "decision=allow" in lower_line:
            story_network_lines.append(line)
    if story_network_lines:
        failures.append(
            "stories preload must not create network file requests before usable success: "
            f"{story_network_lines[0]}"
        )

    sticker_network_lines: list[str] = []
    for line in before_usable:
        lower_line = line.lower()
        if "sticker" not in lower_line and "emoji" not in lower_line and "reaction" not in lower_line:
            continue
        if "upload_getfile" in lower_line or "create load operation" in lower_line:
            sticker_network_lines.append(line)
            continue
        if "proxy_warmup" in lower_line and "class=sticker_prefetch" in lower_line and "decision=allow" in lower_line:
            sticker_network_lines.append(line)
    if sticker_network_lines:
        failures.append(
            "sticker preload must not create network file requests before usable success: "
            f"{sticker_network_lines[0]}"
        )

    for index, line in enumerate(lines):
        if "proxy_warmup state=usable decision=ramp" not in line:
            continue
        if index < first_usable_index:
            failures.append(f"proxy_warmup ramp must wait for first usable success: {line}")
        break

    return failures


def verify_log_noise_and_tlparse(lines: list[str]) -> list[str]:
    failures: list[str] = []
    for line in lines:
        lower_line = line.lower()
        if "received packet size less" in lower_line or "then message size" in lower_line:
            failures.append(f"partial packet assembly must not use failure-looking wording: {line}")
        if "tlparseexception" in lower_line and "upload_file" in lower_line:
            if "tl_parse_drop_answer_ignored" in lower_line:
                continue
            if "e/tmessages" in lower_line or "fatal/tmessages" in lower_line or "fatal" in lower_line:
                failures.append(f"upload_File TLParseException must include context and avoid E/FATAL for drop/cancel responses: {line}")
        if "filestreamloadoperation" in lower_line and ("e/tmessages" in lower_line or "fatal/tmessages" in lower_line):
            failures.append(f"FileStreamLoadOperation lifecycle logs must not use E/tmessages: {line}")
    return failures


def verify_stage2_runtime_rules(lines: list[str]) -> list[str]:
    failures: list[str] = []
    socket_connect_seen: set[str] = set()
    connection_endpoints: dict[str, str] = {}
    usable_successes: list[tuple[int | None, str, str, str]] = []

    for line in lines:
        connection = line_connection(line)
        endpoint = line_endpoint(line, connection_endpoints)
        if connection and endpoint:
            connection_endpoints[connection] = endpoint
        if connection and "mtproxy_startup socket_connect_start" in line:
            socket_connect_seen.add(connection)

        decision = proxy_control_decision(line)
        phase = line_field(line, "phase") or line_field(line, "failed_phase")
        evidence = line_field(line, "evidence")
        response_bytes = line_int_field(line, "response_bytes")

        if decision == "terminal_quarantine" and phase == "handshake_profiles_exhausted":
            failures.append(f"handshake_profiles_exhausted must not terminal_quarantine: {line}")

        next_parser = line_field(line, "next_parser_variant")
        no_byte = evidence == "no_bytes_after_client_hello" or (
            phase in NO_BYTE_AFTER_CLIENT_HELLO_PHASES
            and not (phase == "server_closed_after_client_hello" and response_bytes > 0)
        )
        if next_parser and no_byte and next_parser != STANDARD_HMAC_PARSER:
            failures.append(f"no-byte ClientHello evidence must keep standard_hmac_parser: {line}")

        if phase == "post_handshake_no_appdata" and next_parser and next_parser != STANDARD_HMAC_PARSER:
            failures.append(f"post_handshake_no_appdata must not enter parser recipe cross-product: {line}")

        if "mtproxy_startup phase_adaptive_recipe" in line and line_field(line, "last") == "post_handshake_no_appdata":
            parser_variant = line_field(line, "parser_variant") or line_field(line, "server_hello_parser")
            if parser_variant and parser_variant != STANDARD_HMAC_PARSER:
                failures.append(f"post_handshake_no_appdata must not enter parser recipe cross-product: {line}")

        if connection and phase in PRE_SOCKET_TCP_FAILURE_PHASES and (
            "mtproxy_startup close_diagnostic" in line or "mtproxy_startup endpoint_failure" in line
        ) and connection not in socket_connect_seen:
            failures.append(f"{phase} published before socket_connect_start: {line}")

        if endpoint and (
            "first_tls_app_recv" in line
            or (line_reason(line) == "first_tls_app_recv" and "endpoint_data_path_success" in line)
        ):
            usable_successes.append((line_time_ms(line), endpoint, connection, line))

        sibling_failure = (
            endpoint
            and phase in FRESH_USABLE_FAILURE_OVERWRITE_PHASES
            and (
                "mtproxy_startup close_diagnostic" in line
                or "mtproxy_startup endpoint_failure" in line
                or "mtproxy_startup reconnect_backoff" in line
            )
            and "close_diagnostic_suppressed" not in line
            and "shadowed_socket_failure" not in line
            and "reconnect_backoff_suppressed" not in line
        )
        if not sibling_failure:
            continue
        current_time = line_time_ms(line)
        for success_time, success_endpoint, success_connection, success_line in usable_successes:
            if connection and success_connection and connection == success_connection:
                continue
            if not same_proxy_endpoint(success_endpoint, endpoint):
                continue
            if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                continue
            if phase in POST_SUCCESS_BREAKTHROUGH_FAILURE_PHASES and has_prior_post_success_shadow(lines, line, endpoint, success_time, current_time):
                continue
            failures.append(f"fresh first_tls_app_recv overwritten by sibling socket failure: {line} after {success_line}")
            break

    return failures


def verify_lines(lines: list[str]) -> list[str]:
    failures: list[str] = []
    transport_state_lines = [line for line in lines if "transport_state=" in line]
    handshake_lines = [line for line in lines if "endpoint_handshake_ok" in line]
    data_path_lines = [line for line in lines if "endpoint_data_path_success" in line]
    server_hello_lines = [line for line in lines if "server_hello_hmac_ok" in line]
    disconnect_lines = [line for line in lines if "mtproxy_disconnect" in line]

    if not transport_state_lines:
        failures.append("missing transport_state= evidence in runtime logs")
    if not handshake_lines:
        failures.append("missing endpoint_handshake_ok marker in runtime logs")
    if not data_path_lines:
        failures.append("missing endpoint_data_path_success marker in runtime logs")

    if server_hello_lines and not any(line_reason(line) == "server_hello_hmac_ok" for line in handshake_lines):
        failures.append("server_hello_hmac_ok must produce endpoint_handshake_ok reason=server_hello_hmac_ok")

    for line in handshake_lines:
        reason = line_reason(line)
        if reason and reason != "server_hello_hmac_ok":
            failures.append(f"endpoint_handshake_ok must use reason=server_hello_hmac_ok: {line}")

    for index, line in enumerate(lines):
        if "endpoint_data_path_success" not in line:
            continue
        reason = line_reason(line)
        if reason == "server_hello_hmac_ok":
            failures.append("endpoint_data_path_success must not use reason=server_hello_hmac_ok")
        elif reason not in ALLOWED_DATA_PATH_REASONS:
            failures.append(
                "endpoint_data_path_success must use reason=first_tls_app_recv "
                f"or first_mtproxy_packet_recv: {line}"
            )
        elif not has_prior_connection_marker(lines, index, line_connection(line), f"mtproxy_startup {reason}"):
            failures.append(
                f"endpoint_data_path_success reason={reason} must be preceded by {reason} "
                f"app-data marker on the same connection: {line}"
            )

    for line in disconnect_lines:
        missing = [field for field in DISCONNECT_REQUIRED_FIELDS if field not in line]
        if missing:
            failures.append(f"mtproxy_disconnect missing invariant fields {','.join(missing)}: {line}")

    failures.extend(verify_visible_success_hold(lines))
    failures.extend(verify_one_shot_terminal(lines))
    failures.extend(verify_server_hello_diagnostics(lines))
    failures.extend(verify_shadowed_socket_backoff(lines))
    failures.extend(verify_usable_hold_anchor(lines))
    failures.extend(verify_dns_visible_debounce(lines))
    failures.extend(verify_rotation_hysteresis(lines))
    failures.extend(verify_dns_outage_rotation_hold(lines))
    failures.extend(verify_rotated_away_endpoint_hold(lines))
    failures.extend(verify_dns_resolver_logs(lines))
    failures.extend(verify_startup_warmup_fanout(lines))
    failures.extend(verify_log_noise_and_tlparse(lines))
    failures.extend(verify_failure_evidence(lines))
    failures.extend(verify_stage2_runtime_rules(lines))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a collect_mtproxy_logs session directory or mtproxy_markers.txt",
    )
    args = parser.parse_args()

    marker_path = resolve_markers_path(args.path)
    failures = verify_lines(read_lines(marker_path))
    if failures:
        print("MTProxy runtime log contract failed:", file=__import__("sys").stderr)
        for failure in failures:
            print(f" - {failure}", file=__import__("sys").stderr)
        return 1

    print("MTProxy runtime log contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
