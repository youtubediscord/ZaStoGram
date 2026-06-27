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


REASON_RE = re.compile(r"(?<![A-Za-z0-9_])reason=([^ ]+)")
CONNECTION_RE = re.compile(r"connection\((0x[0-9a-fA-F]+)\)")
LOG_TIME_RE = re.compile(r"\b(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})\b")
PROXY_CONTROL_RE = re.compile(r"proxy_control decision=([^ ]+)")
FIELD_RE_TEMPLATE = r"(?<![A-Za-z0-9_]){}=([^ ]+)"
DISCONNECT_REQUIRED_FIELDS = (
    "transport_state=",
    "epoll_registered=",
    "admission_active=",
    "tcp_gate_active=",
)
ALLOWED_DATA_PATH_REASONS = {"first_tls_app_recv", "first_mtproxy_packet_recv"}
USABLE_SUCCESS_PROXY_PHASES = {"first_tls_app_recv", "first_mtproxy_packet_recv"}
VISIBLE_SUCCESS_HOLD_MS = 45 * 1000
LIVE_VISIBLE_OVERWRITE_PHASES = {
    "dns_cache_hit",
    "dns_cache_store",
    "dns_coalesce_wait",
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
PUNITIVE_ROTATION_PHASES = {
    "tcp_not_connected",
    "host_resolve_failed",
    "host_resolve_timeout",
    "tcp_connected_no_pong",
    "client_hello_sent_no_server_hello",
    "server_hello_hmac_mismatch",
    "mtproxy_packet_sent_no_response",
    "post_handshake_no_appdata",
    "dropped_early_after_appdata",
}
ROTATION_HYSTERESIS_WINDOW_MS = 30 * 1000
ROTATION_FAILURES_TO_TRIGGER = 2


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


def proxy_control_decision(line: str) -> str:
    match = PROXY_CONTROL_RE.search(line)
    return match.group(1) if match else ""


def same_proxy_endpoint(left: str, right: str) -> bool:
    return bool(left and right and (left == right or left.startswith(right) or right.startswith(left)))


def has_prior_connection_marker(lines: list[str], index: int, connection: str, marker: str) -> bool:
    for candidate in lines[:index]:
        if marker not in candidate:
            continue
        if connection and line_connection(candidate) != connection:
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
        if decision == "visible_usable_success" and phase in USABLE_SUCCESS_PROXY_PHASES:
            usable_successes.append((line_time_ms(line), endpoint, line))
            continue
        if decision != "visible_only" or phase not in LIVE_VISIBLE_OVERWRITE_PHASES:
            continue
        current_time = line_time_ms(line)
        for success_time, success_endpoint, success_line in usable_successes:
            if not same_proxy_endpoint(success_endpoint, endpoint):
                continue
            if success_time is not None and current_time is not None and current_time - success_time > VISIBLE_SUCCESS_HOLD_MS:
                continue
            failures.append(
                "visible usable success overwritten by live visible_only within 45s: "
                f"{line} after {success_line}"
            )
            break
    return failures


def verify_rotation_hysteresis(lines: list[str]) -> list[str]:
    failures: list[str] = []
    usable_successes: list[tuple[int | None, str, str]] = []
    for line in lines:
        if proxy_control_decision(line) == "visible_usable_success" and line_field(line, "phase") in USABLE_SUCCESS_PROXY_PHASES:
            usable_successes.append((line_time_ms(line), line_field(line, "endpoint"), line))
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
    failures.extend(verify_rotation_hysteresis(lines))

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
