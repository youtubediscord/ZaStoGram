#!/usr/bin/env python3
"""Summarize MTProxy FakeTLS lifecycle markers from collect_mtproxy_logs.ps1.

The analyzer is intentionally conservative: it does not try to prove DPI by
itself. It groups log markers by ConnectionSocket pointer and shows the exact
phase where each attempt stopped, so VPN/non-VPN captures can be compared.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


CONNECTION_RE = re.compile(r"connection\((0x[0-9a-fA-F]+)")
ACCOUNT_CONNECT_RE = re.compile(
    r"connection\((0x[0-9a-fA-F]+), account([0-9]+), dc([0-9]+), type ([0-9]+)\) connecting \(([^)]+)\)"
)
ACCOUNT_LINE_RE = re.compile(
    r"connection\((0x[0-9a-fA-F]+), account([0-9]+), dc([0-9]+), type ([0-9]+)\) (.*)"
)
PROXY_CONNECT_RE = re.compile(r"connecting via proxy ([^ ]+) secret\[([0-9]+)\] secret_kind=([^ ]+)")
PROFILE_RE = re.compile(r"profile selected=([a-z_]+)(?: id=([0-9]+))?(?: hello=([0-9]+))?")
CONNECT_RE = re.compile(r"connect_start .*profile=([a-z_]+).*address=([^ ]+) port=([0-9]+)")
ADMISSION_KEY_RE = re.compile(r"admission_[a-z_]+ .*key=([^ ]+)(?: priority=([-0-9]+))?")
CLIENT_HELLO_SENT_RE = re.compile(r"client_hello_sent bytes=([0-9]+)")
DISCONNECT_RE = re.compile(
    r"mtproxy_disconnect reason=([-0-9]+).*?error=([-0-9]+).*?"
    r"proxy_state=([-0-9]+) tls_state=([-0-9]+) bytes_read=([0-9]+)"
)
PROXY_CHECK_RE = re.compile(r"proxy_check_([a-z_]+)")
PROXY_CHECK_SCHEDULER_RE = re.compile(r"proxy_check_scheduler ([a-z_]+)")
PROXY_CHECK_START_RE = re.compile(r"proxy_check_start .*ping_id=([0-9]+).*address=([^ ]+)")
PROXY_CHECK_SOCKET_RE = re.compile(r"proxy_check_socket_connected ping_id=([0-9]+)")
PROXY_CHECK_RESULT_RE = re.compile(r"proxy_check_finish result=([a-z]+) reason=([^ ]+)")
PROXY_CHECK_FINISH_RE = re.compile(r"proxy_check_finish result=([a-z]+) reason=([^ ]+).*ping_id=([0-9]+) address=([^ ]+)")
PROXY_CHECK_DIAGNOSTIC_RE = re.compile(r"proxy_check_finish .*diagnostic=([^ ]+)")
PROXY_CHECK_START_FAILED_RE = re.compile(r"proxy_check_start_failed reason=([^ ]+)")
PROXY_CHECK_CLOSE_RE = re.compile(r"proxy_check_connection_closed close_reason=([-0-9]+)")
PROXY_CHECK_CLOSE_WITH_PING_RE = re.compile(r"proxy_check_connection_closed close_reason=([-0-9]+) ping_id=([0-9]+)")
PROXY_CHECK_IGNORED_CLOSE_RE = re.compile(r"proxy_check_connection_closed_ignored close_reason=([-0-9]+)")
PROXY_ROTATION_RE = re.compile(r"proxy_rotation ([a-z_]+)")
ENDPOINT_RE = re.compile(r"endpoint=([^ ]+)")
SCHEDULER_LISTENERS_RE = re.compile(r"listeners=([0-9]+)")
SCHEDULER_FORCE_RE = re.compile(r"force=(true|false)")
SCHEDULER_RESULT_RE = re.compile(r"proxy_check_scheduler finish result=([a-z]+)")
SCHEDULER_APPLIED_RE = re.compile(r"time=([-0-9]+) applied_time=([-0-9]+) raw_time=([-0-9]+)")
TIME_RE = re.compile(r"^[0-9]{2}-[0-9]{2} ([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})")

FAKETLS_FAILURE_VERDICTS = {
    "tcp_not_connected",
    "connected_but_client_hello_not_fully_sent",
    "client_hello_sent_no_server_hello",
    "server_hello_hmac_mismatch",
    "hmac_ok_but_on_connected_not_reached",
    "post_handshake_no_appdata",
    "peer_closed_after_client_hello",
}


@dataclass
class Attempt:
    key: str
    first_line: int = 0
    last_line: int = 0
    lines: list[str] = field(default_factory=list)
    events: Counter[str] = field(default_factory=Counter)
    profile: str = ""
    profile_id: str = ""
    hello_bytes: str = ""
    client_hello_bytes: str = ""
    address: str = ""
    port: str = ""
    endpoint: str = ""
    proxy_key: str = ""
    proxy_endpoint: str = ""
    secret_kind: str = ""
    secret_len: str = ""
    account: str = ""
    dc: str = ""
    connection_type: str = ""
    telegram_endpoint: str = ""
    priority: str = ""
    disconnect: str = ""
    disconnect_reason: str = ""
    disconnect_error: str = ""
    first_time: str = ""
    first_seconds: float = 0.0
    event_times: dict[str, float] = field(default_factory=dict)

    def endpoint_text(self) -> str:
        if self.endpoint:
            return self.endpoint
        if self.proxy_endpoint:
            return self.proxy_endpoint
        if self.address:
            return f"{self.address}:{self.port}"
        return "unknown"

    def is_faketls(self) -> bool:
        return (
            self.secret_kind == "ee"
            or bool(self.proxy_key)
            or self.events["client_hello_sent"] > 0
            or self.events["server_hello_hmac_ok"] > 0
        )

    def timing_ms(self, start_event: str, end_event: str) -> str:
        start = self.event_times.get(start_event)
        end = self.event_times.get(end_event)
        if start is None or end is None:
            return ""
        return str(round((end - start) * 1000))

    def add(self, line_no: int, text: str) -> None:
        if not self.first_line:
            self.first_line = line_no
            self.first_time = log_time_label(text)
            self.first_seconds = log_time_seconds(text)
        self.last_line = line_no
        self.lines.append(text)

        account_connect = ACCOUNT_CONNECT_RE.search(text)
        if account_connect:
            self.account = account_connect.group(2)
            self.dc = account_connect.group(3)
            self.connection_type = account_connect.group(4)
            self.telegram_endpoint = account_connect.group(5)

        account_line = ACCOUNT_LINE_RE.search(text)
        if account_line:
            self.account = account_line.group(2)
            self.dc = account_line.group(3)
            self.connection_type = account_line.group(4)
            account_event = account_line.group(5)
            if account_event.startswith("connected to "):
                self.events["account_connected"] += 1
            if account_event.startswith("send message "):
                self.events["account_send_message"] += 1
            if account_event.startswith("received message "):
                self.events["account_received_message"] += 1
            if "received rpc_result" in account_event:
                self.events["account_rpc_result"] += 1
            if "reset auth key due to -404" in account_event:
                self.events["account_auth_404"] += 1
            if "received invalid packet length" in account_event:
                self.events["account_invalid_packet_length"] += 1
            disconnect_match = re.search(r"disconnected with reason ([-0-9]+)", account_event)
            if disconnect_match:
                self.events[f"account_disconnect_{disconnect_match.group(1)}"] += 1

        proxy_connect = PROXY_CONNECT_RE.search(text)
        if proxy_connect:
            self.proxy_endpoint = proxy_connect.group(1)
            self.secret_len = proxy_connect.group(2)
            self.secret_kind = proxy_connect.group(3)

        connect = CONNECT_RE.search(text)
        if connect:
            self.profile = connect.group(1)
            self.address = connect.group(2)
            self.port = connect.group(3)
            self.telegram_endpoint = f"{self.address}:{self.port}"

        admission_key = ADMISSION_KEY_RE.search(text)
        if admission_key:
            self.proxy_key = admission_key.group(1)
            self.endpoint = endpoint_from_admission_key(self.proxy_key)
            if admission_key.group(2):
                self.priority = admission_key.group(2)

        profile = PROFILE_RE.search(text)
        if profile:
            self.profile = profile.group(1)
            if profile.group(2):
                self.profile_id = profile.group(2)
            if profile.group(3):
                self.hello_bytes = profile.group(3)

        client_hello = CLIENT_HELLO_SENT_RE.search(text)
        if client_hello:
            self.client_hello_bytes = client_hello.group(1)

        disconnect = DISCONNECT_RE.search(text)
        if disconnect:
            self.disconnect_reason = disconnect.group(1)
            self.disconnect_error = disconnect.group(2)
            self.disconnect = (
                f"reason={disconnect.group(1)} error={disconnect.group(2)} "
                f"proxy_state={disconnect.group(3)} tls_state={disconnect.group(4)} "
                f"bytes_read={disconnect.group(5)}"
            )

        event_map = {
            "connect_start": "connect_start",
            "socket_connect_start": "socket_connect_start",
            "socket_connected": "socket_connected",
            "client_hello_send_progress": "client_hello_send_progress",
            "client_hello_sent": "client_hello_sent",
            "server_hello_hmac_ok": "server_hello_hmac_ok",
            "server_hello_hmac_timeout": "server_hello_hmac_timeout",
            "server_hello_timeout_close": "server_hello_timeout_close",
            "TLS server hello hmac wait": "server_hello_hmac_wait",
            "admission_freeze_detected": "admission_freeze_detected",
            "on_connected": "on_connected",
            "first_tls_app_sent": "first_tls_app_sent",
            "first_tls_app_recv": "first_tls_app_recv",
            "tls_alert": "tls_alert",
            "recv_eof": "recv_eof",
            "EPOLLHUP": "epoll_hup",
            "EPOLLRDHUP": "epoll_rdhup",
            "socket error": "socket_error",
            "TLS response version mismatch": "tls_response_version_mismatch",
            "TLS response record type mismatch": "tls_response_record_type_mismatch",
        }
        for needle, event in event_map.items():
            if needle in text:
                self.events[event] += 1
                self.event_times.setdefault(event, log_time_seconds(text))

    def verdict(self) -> str:
        has = self.events.__contains__
        if has("on_connected") and not has("socket_connected"):
            return "connected_without_socket_connected_marker"
        if not has("socket_connected"):
            return "tcp_not_connected"
        if not has("client_hello_sent"):
            return "connected_but_client_hello_not_fully_sent"
        if not has("server_hello_hmac_ok"):
            if has("server_hello_hmac_timeout") or has("server_hello_hmac_wait"):
                return "server_hello_hmac_mismatch"
            if has("server_hello_timeout_close") or has("admission_freeze_detected"):
                return "client_hello_sent_no_server_hello"
            if has("recv_eof"):
                return "peer_closed_after_client_hello"
            return "client_hello_sent_no_server_hello"
        if not has("on_connected"):
            return "hmac_ok_but_on_connected_not_reached"
        if has("first_tls_app_sent") and not has("first_tls_app_recv"):
            return "post_handshake_no_appdata"
        if has("first_tls_app_recv"):
            return "ok"
        return "post_handshake_no_appdata"

    def compact(self) -> str:
        parts = [
            self.first_time or f"line {self.first_line}",
            self.endpoint_text(),
            f"profile={profile_text(self)}",
            f"phase={self.verdict()}",
        ]
        if self.hello_bytes:
            parts.append(f"hello={self.hello_bytes}")
        if self.connection_type:
            parts.append(f"type={self.connection_type}")
        if self.priority:
            parts.append(f"priority={self.priority}")
        if (hmac_ms := self.timing_ms("client_hello_sent", "server_hello_hmac_ok")):
            parts.append(f"hmac_ms={hmac_ms}")
        if self.disconnect_reason:
            parts.append(f"close={self.disconnect_reason}/{self.disconnect_error}")
        return " ".join(parts)


def marker_text(line: str) -> tuple[int, str]:
    # collect_mtproxy_logs.ps1 writes: path:line_number: original log line
    match = re.match(r"^.*?:([0-9]+):\s*(.*)$", line.rstrip("\n"))
    if match:
        prefix = line[: match.start(1) - 1]
        if "/" not in prefix and "\\" not in prefix and not prefix.endswith((".txt", ".log")):
            return 0, line.rstrip("\n")
        return int(match.group(1)), match.group(2)
    return 0, line.rstrip("\n")


def log_time_seconds(text: str) -> float:
    match = TIME_RE.match(text)
    if not match:
        return 0.0
    hours, minutes, seconds, millis = [int(part) for part in match.groups()]
    return hours * 3600 + minutes * 60 + seconds + millis / 1000.0


def log_time_label(text: str) -> str:
    match = TIME_RE.match(text)
    if not match:
        return ""
    return text[:18]


def endpoint_from_admission_key(proxy_key: str) -> str:
    match = re.match(r"^(.+):([0-9]+):.+$", proxy_key)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return proxy_key


def profile_text(attempt: Attempt) -> str:
    if attempt.profile:
        return attempt.profile
    if attempt.events["client_hello_sent"]:
        return "unknown_profile"
    return "no_profile_before_clienthello"


def is_connect_start(text: str) -> bool:
    return "mtproxy_startup connect_start " in text


def is_socket_connect_start(text: str) -> bool:
    return "mtproxy_startup socket_connect_start" in text


def is_proxy_connect(text: str) -> bool:
    return "connecting via proxy " in text


def load_attempts(path: Path) -> tuple[list[Attempt], list[str]]:
    attempts: dict[str, Attempt] = {}
    global_lines: list[str] = []
    sequence_by_key: defaultdict[str, int] = defaultdict(int)
    active_key_by_pointer: dict[str, str] = {}
    pending_account_by_pointer: dict[str, tuple[str, str, str, str]] = {}

    def apply_pending_account(pointer: str, attempt: Attempt) -> None:
        pending = pending_account_by_pointer.get(pointer)
        if not pending:
            return
        attempt.account, attempt.dc, attempt.connection_type, attempt.telegram_endpoint = pending

    def new_attempt(pointer: str) -> Attempt:
        if sequence_by_key[pointer] == 0:
            key = pointer
        else:
            key = f"{pointer}#{sequence_by_key[pointer]}"
        sequence_by_key[pointer] += 1
        attempt = Attempt(key=key)
        attempts[key] = attempt
        active_key_by_pointer[pointer] = key
        apply_pending_account(pointer, attempt)
        return attempt

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip() == "No MTProxy markers found.":
            continue
        line_no, text = marker_text(raw)
        connection = CONNECTION_RE.search(text)
        if not connection:
            global_lines.append(text)
            continue

        pointer = connection.group(1)
        current_key = active_key_by_pointer.get(pointer)
        account_connect = ACCOUNT_CONNECT_RE.search(text)
        if account_connect:
            pending_account_by_pointer[pointer] = (
                account_connect.group(2),
                account_connect.group(3),
                account_connect.group(4),
                account_connect.group(5),
            )
            if current_key is None:
                global_lines.append(text)
                continue

        if is_proxy_connect(text):
            attempt = new_attempt(pointer)
        elif is_connect_start(text):
            if current_key is not None and attempts[current_key].events["connect_start"] == 0:
                attempt = attempts[current_key]
            else:
                attempt = new_attempt(pointer)
        elif is_socket_connect_start(text):
            if current_key is None:
                attempt = new_attempt(pointer)
            else:
                current_attempt = attempts[current_key]
                if current_attempt.events["socket_connect_start"]:
                    attempt = new_attempt(pointer)
                else:
                    attempt = current_attempt
        elif current_key is None:
            attempt = new_attempt(pointer)
        else:
            attempt = attempts[current_key]
        attempt.add(line_no, text)
        if "mtproxy_disconnect" in text:
            active_key_by_pointer.pop(pointer, None)

    return sorted(attempts.values(), key=lambda item: (item.first_line, item.key)), global_lines


def print_proxy_check_summary(lines: list[str]) -> None:
    native_events: Counter[str] = Counter()
    native_results: Counter[str] = Counter()
    native_endpoint_outcomes: Counter[str] = Counter()
    native_start_failures: Counter[str] = Counter()
    native_close_reasons: Counter[str] = Counter()
    native_ignored_close_reasons: Counter[str] = Counter()
    scheduler_events: Counter[str] = Counter()
    scheduler_endpoints: Counter[str] = Counter()
    scheduler_coalescing: Counter[str] = Counter()
    scheduler_listener_peaks: dict[str, int] = {}
    scheduler_force: Counter[str] = Counter()
    scheduler_results: Counter[str] = Counter()
    scheduler_preserved_connected: Counter[str] = Counter()
    scheduler_applied_split: Counter[str] = Counter()
    rotation_events: Counter[str] = Counter()
    proxy_checks: dict[str, dict[str, str | bool]] = {}

    for text in lines:
        rotation = PROXY_ROTATION_RE.search(text)
        if rotation:
            rotation_events[rotation.group(1)] += 1

        if "proxy_check_scheduler " in text:
            scheduler = PROXY_CHECK_SCHEDULER_RE.search(text)
            event = ""
            if scheduler:
                event = scheduler.group(1)
                scheduler_events[event] += 1
            endpoint = ENDPOINT_RE.search(text)
            if endpoint:
                endpoint_text = endpoint.group(1)
                scheduler_endpoints[endpoint_text] += 1
                listeners = SCHEDULER_LISTENERS_RE.search(text)
                if listeners:
                    scheduler_listener_peaks[endpoint_text] = max(
                        scheduler_listener_peaks.get(endpoint_text, 0),
                        int(listeners.group(1)),
                    )
                if event in {"attach_pending", "enqueue_now", "cancel_owner"}:
                    scheduler_coalescing[f"{event} endpoint={endpoint_text}"] += 1
            force = SCHEDULER_FORCE_RE.search(text)
            if force:
                scheduler_force[force.group(1)] += 1
            result = SCHEDULER_RESULT_RE.search(text)
            if result:
                scheduler_results[result.group(1)] += 1
                applied = SCHEDULER_APPLIED_RE.search(text)
                if applied and (applied.group(1) != applied.group(2) or applied.group(1) != applied.group(3)):
                    scheduler_applied_split[f"callback={applied.group(1)} applied={applied.group(2)} raw={applied.group(3)}"] += 1
            if event == "finish_keep_connected":
                endpoint = ENDPOINT_RE.search(text)
                scheduler_preserved_connected[endpoint.group(1) if endpoint else "unknown"] += 1
            continue

        native = PROXY_CHECK_RE.search(text)
        if native:
            native_events[native.group(1)] += 1
            start = PROXY_CHECK_START_RE.search(text)
            if start:
                proxy_checks[start.group(1)] = {
                    "endpoint": start.group(2),
                    "socket_connected": False,
                    "close_reason": "",
                }
            socket = PROXY_CHECK_SOCKET_RE.search(text)
            if socket:
                proxy_checks.setdefault(socket.group(1), {"endpoint": "unknown", "socket_connected": False, "close_reason": ""})[
                    "socket_connected"
                ] = True
            close_with_ping = PROXY_CHECK_CLOSE_WITH_PING_RE.search(text)
            if close_with_ping:
                proxy_checks.setdefault(close_with_ping.group(2), {"endpoint": "unknown", "socket_connected": False, "close_reason": ""})[
                    "close_reason"
                ] = close_with_ping.group(1)
            start_failed = PROXY_CHECK_START_FAILED_RE.search(text)
            if start_failed:
                native_start_failures[start_failed.group(1)] += 1
            result = PROXY_CHECK_RESULT_RE.search(text)
            if result:
                native_results[f"{result.group(1)}:{result.group(2)}"] += 1
            finish = PROXY_CHECK_FINISH_RE.search(text)
            if finish:
                result_text = finish.group(1)
                reason_text = finish.group(2)
                ping_id = finish.group(3)
                endpoint_text = finish.group(4)
                state = proxy_checks.setdefault(
                    ping_id,
                    {"endpoint": endpoint_text, "socket_connected": False, "close_reason": ""},
                )
                state["endpoint"] = endpoint_text
                close_reason = state.get("close_reason") or "none"
                if result_text == "ok":
                    outcome = f"{endpoint_text} ok:{reason_text}"
                elif (diagnostic := PROXY_CHECK_DIAGNOSTIC_RE.search(text)):
                    outcome = f"{endpoint_text} fail:{diagnostic.group(1)} close_reason={close_reason}"
                elif state.get("socket_connected"):
                    outcome = f"{endpoint_text} fail:tcp_connected_no_pong close_reason={close_reason}"
                else:
                    outcome = f"{endpoint_text} fail:tcp_not_connected close_reason={close_reason}"
                native_endpoint_outcomes[outcome] += 1
            close = PROXY_CHECK_CLOSE_RE.search(text)
            if close:
                native_close_reasons[close.group(1)] += 1
            ignored_close = PROXY_CHECK_IGNORED_CLOSE_RE.search(text)
            if ignored_close:
                native_ignored_close_reasons[ignored_close.group(1)] += 1

    if not native_events and not scheduler_events and not rotation_events:
        return

    print()
    print("Proxy-check lifecycle:")
    if rotation_events:
        print("  Rotation events:")
        for event, count in rotation_events.most_common():
            print(f"    {event}: {count}")
    if scheduler_events:
        print("  Java scheduler events:")
        for event, count in scheduler_events.most_common():
            print(f"    {event}: {count}")
    if scheduler_coalescing:
        print("  Scheduler coalescing:")
        for item, count in scheduler_coalescing.most_common(10):
            print(f"    {item}: {count}")
    if scheduler_listener_peaks:
        print("  Scheduler listener peaks:")
        for endpoint, count in sorted(scheduler_listener_peaks.items(), key=lambda item: (-item[1], item[0]))[:10]:
            print(f"    {endpoint}: {count}")
    if scheduler_force:
        print("  Scheduler force flags:")
        for value, count in scheduler_force.most_common():
            print(f"    {value}: {count}")
    if scheduler_results:
        print("  Scheduler finish results:")
        for result, count in scheduler_results.most_common():
            print(f"    {result}: {count}")
    if scheduler_preserved_connected:
        print("  Scheduler preserved connected state:")
        for endpoint, count in scheduler_preserved_connected.most_common(10):
            print(f"    {endpoint}: {count}")
    if scheduler_applied_split:
        print("  Scheduler applied/callback split:")
        for item, count in scheduler_applied_split.most_common(10):
            print(f"    {item}: {count}")
    if native_events:
        print("  Native events:")
        for event, count in native_events.most_common():
            print(f"    {event}: {count}")
    if native_results:
        print("  Native finish results:")
        for result, count in native_results.most_common():
            print(f"    {result}: {count}")
    if native_endpoint_outcomes:
        print("  Native endpoint outcomes:")
        for result, count in native_endpoint_outcomes.most_common():
            print(f"    {result}: {count}")
    if native_start_failures:
        print("  Native start failures:")
        for reason, count in native_start_failures.most_common():
            print(f"    {reason}: {count}")
    if native_close_reasons:
        print("  Native close reasons:")
        for reason, count in native_close_reasons.most_common():
            print(f"    {reason}: {count}")
    if native_ignored_close_reasons:
        print("  Native ignored close reasons:")
        for reason, count in native_ignored_close_reasons.most_common():
            print(f"    {reason}: {count}")
    if scheduler_endpoints:
        print("  Scheduler endpoints:")
        for endpoint, count in scheduler_endpoints.most_common(10):
            print(f"    {endpoint}: {count}")


def print_faketls_endpoint_summary(attempts: list[Attempt]) -> None:
    attempts = faketls_attempts(attempts)
    endpoint_verdicts: Counter[str] = Counter()
    endpoint_profile_verdicts: Counter[str] = Counter()
    for attempt in attempts:
        endpoint = attempt.endpoint_text()
        endpoint_verdicts[f"{endpoint} {attempt.verdict()}"] += 1
        if attempt.profile or attempt.secret_kind == "ee":
            endpoint_profile_verdicts[f"{endpoint} {profile_text(attempt)} {attempt.verdict()}"] += 1

    if not endpoint_verdicts:
        return

    print()
    print("FakeTLS endpoint phases:")
    for item, count in endpoint_verdicts.most_common(30):
        print(f"  {item}: {count}")

    if endpoint_profile_verdicts:
        print()
        print("FakeTLS endpoint/profile phases:")
        for item, count in endpoint_profile_verdicts.most_common(30):
            print(f"  {item}: {count}")


def print_plain_mtproxy_summary(attempts: list[Attempt]) -> None:
    plain_attempts = [
        attempt
        for attempt in attempts
        if attempt.secret_kind and attempt.secret_kind != "ee" and not attempt.events["client_hello_sent"]
    ]
    if not plain_attempts:
        return

    by_flow: defaultdict[tuple[str, str, str, str, str], Counter[str]] = defaultdict(Counter)
    for attempt in plain_attempts:
        key = (
            attempt.endpoint_text(),
            attempt.secret_kind,
            attempt.account or "unknown",
            attempt.dc or "unknown",
            attempt.connection_type or "unknown",
        )
        stats = by_flow[key]
        stats["connected"] += 1 if attempt.events["on_connected"] or attempt.events["account_connected"] else 0
        stats["send"] += attempt.events["account_send_message"]
        stats["recv"] += attempt.events["account_received_message"]
        stats["rpc_result"] += attempt.events["account_rpc_result"]
        stats["invalid_packet_length"] += attempt.events["account_invalid_packet_length"]
        stats["auth_404"] += attempt.events["account_auth_404"]
        for event, count in attempt.events.items():
            if event.startswith("account_disconnect_"):
                stats[event.replace("account_", "")] += count

    if not by_flow:
        return

    print()
    print("Plain MTProxy lifecycle:")
    for (endpoint, secret_kind, account, dc, connection_type), stats in sorted(
        by_flow.items(),
        key=lambda item: (
            -item[1]["send"],
            item[0][0],
            item[0][2],
            item[0][3],
            int(item[0][4]) if item[0][4].isdigit() else 0,
        ),
    )[:40]:
        parts = [
            f"{endpoint} {secret_kind} account{account} dc{dc} type{connection_type}:",
            f"connected={stats['connected']}",
            f"send={stats['send']}",
            f"recv={stats['recv']}",
            f"rpc_result={stats['rpc_result']}",
        ]
        if stats["invalid_packet_length"]:
            parts.append(f"invalid_packet_length={stats['invalid_packet_length']}")
        if stats["auth_404"]:
            parts.append(f"auth_404={stats['auth_404']}")
        for event, count in sorted(stats.items()):
            if event.startswith("disconnect_") and count:
                parts.append(f"{event}={count}")
        print("  " + " ".join(parts))


def print_faketls_profile_summary(attempts: list[Attempt]) -> None:
    profile_verdicts: Counter[str] = Counter()
    profile_hmac_ms: defaultdict[str, list[int]] = defaultdict(list)
    for attempt in attempts:
        if not attempt.is_faketls() or (attempt.secret_kind and attempt.secret_kind != "ee"):
            continue
        profile = profile_text(attempt)
        profile_verdicts[f"{profile} {attempt.verdict()}"] += 1
        hmac_ms = attempt.timing_ms("client_hello_sent", "server_hello_hmac_ok")
        if hmac_ms:
            profile_hmac_ms[profile].append(int(hmac_ms))

    if not profile_verdicts:
        return

    print()
    print("FakeTLS profile phases:")
    for item, count in profile_verdicts.most_common():
        print(f"  {item}: {count}")

    if profile_hmac_ms:
        print()
        print("FakeTLS profile HMAC latency:")
        for profile, values in sorted(profile_hmac_ms.items()):
            values.sort()
            mid = values[len(values) // 2]
            print(f"  {profile}: n={len(values)} min={values[0]}ms p50={mid}ms max={values[-1]}ms")


def faketls_attempts(attempts: list[Attempt]) -> list[Attempt]:
    return [
        attempt
        for attempt in attempts
        if attempt.is_faketls() and (not attempt.secret_kind or attempt.secret_kind == "ee")
    ]


def percentile(values: list[int], percent: int) -> str:
    if not values:
        return ""
    values = sorted(values)
    index = round((len(values) - 1) * percent / 100)
    return str(values[index])


def ok_percent(ok: int, total: int) -> str:
    if total <= 0:
        return "0%"
    return f"{round(ok * 100 / total)}%"


def max_attempts_in_window(attempts: list[Attempt], seconds: float) -> int:
    times = sorted(attempt.first_seconds for attempt in attempts if attempt.first_seconds > 0)
    if not times:
        return 0
    best = 1
    left = 0
    for right, value in enumerate(times):
        while value - times[left] > seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def top_failures(verdicts: Counter[str]) -> str:
    failures = [
        f"{verdict}={count}"
        for verdict, count in verdicts.most_common()
        if verdict != "ok"
    ]
    return ", ".join(failures[:3]) if failures else "none"


def print_faketls_reliability_summary(attempts: list[Attempt]) -> None:
    attempts = faketls_attempts(attempts)
    if not attempts:
        return

    by_profile: defaultdict[str, list[Attempt]] = defaultdict(list)
    by_endpoint_profile: defaultdict[tuple[str, str], list[Attempt]] = defaultdict(list)
    by_endpoint: defaultdict[str, list[Attempt]] = defaultdict(list)
    for attempt in attempts:
        profile = profile_text(attempt)
        endpoint = attempt.endpoint_text()
        by_profile[profile].append(attempt)
        by_endpoint_profile[(endpoint, profile)].append(attempt)
        by_endpoint[endpoint].append(attempt)

    print()
    print("FakeTLS reliability:")
    print("  By profile:")
    for profile, items in sorted(by_profile.items(), key=lambda item: (-len(item[1]), item[0])):
        verdicts = Counter(item.verdict() for item in items)
        hmac_values = [
            int(value)
            for item in items
            if (value := item.timing_ms("client_hello_sent", "server_hello_hmac_ok"))
        ]
        print(
            "    "
            f"{profile}: total={len(items)} ok={verdicts['ok']} ok_rate={ok_percent(verdicts['ok'], len(items))} "
            f"pre_server_hello={verdicts['client_hello_sent_no_server_hello']} "
            f"post_handshake={verdicts['post_handshake_no_appdata']} "
            f"hmac_fail={verdicts['server_hello_hmac_mismatch']} "
            f"hmac_p50={percentile(hmac_values, 50) or '-'}ms"
        )

    suspicious = []
    for (endpoint, profile), items in by_endpoint_profile.items():
        verdicts = Counter(item.verdict() for item in items)
        failures = len(items) - verdicts["ok"]
        if len(items) < 2 or failures == 0:
            continue
        suspicious.append((failures, len(items), endpoint, profile, verdicts))
    suspicious.sort(key=lambda item: (-item[0], -item[1], item[2], item[3]))
    if suspicious:
        print("  Top failing endpoint/profile clusters:")
        for failures, total, endpoint, profile, verdicts in suspicious[:20]:
            print(
                "    "
                f"{endpoint} {profile}: total={total} ok={verdicts['ok']} "
                f"ok_rate={ok_percent(verdicts['ok'], total)} failures={failures} "
                f"{top_failures(verdicts)}"
            )

    burst_rows = []
    for endpoint, items in by_endpoint.items():
        one_second = max_attempts_in_window(items, 1.0)
        five_seconds = max_attempts_in_window(items, 5.0)
        if one_second >= 2 or five_seconds >= 3:
            verdicts = Counter(item.verdict() for item in items)
            profiles = Counter(profile_text(item) for item in items)
            burst_rows.append((five_seconds, one_second, len(items), endpoint, verdicts, profiles))
    burst_rows.sort(key=lambda item: (-item[0], -item[1], -item[2], item[3]))
    if burst_rows:
        print("  Endpoint handshake bursts:")
        for five_seconds, one_second, total, endpoint, verdicts, profiles in burst_rows[:20]:
            profile_mix = ", ".join(f"{profile}={count}" for profile, count in profiles.most_common(3))
            print(
                "    "
                f"{endpoint}: total={total} max_1s={one_second} max_5s={five_seconds} "
                f"ok={verdicts['ok']} failures={total - verdicts['ok']} profiles={profile_mix}"
            )


def print_faketls_failure_timeline(attempts: list[Attempt]) -> None:
    interesting = [
        attempt
        for attempt in attempts
        if attempt.is_faketls()
        and (not attempt.secret_kind or attempt.secret_kind == "ee")
        and attempt.verdict()
        in {
            "client_hello_sent_no_server_hello",
            "server_hello_hmac_mismatch",
            "post_handshake_no_appdata",
            "hmac_ok_but_on_connected_not_reached",
        }
    ]
    if not interesting:
        return

    print()
    print("FakeTLS failure timeline:")
    for attempt in interesting[:80]:
        print(f"  {attempt.compact()}")


def write_csv_reports(attempts: list[Attempt], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    all_attempts = attempts
    attempts = faketls_attempts(attempts)

    attempts_path = out_dir / "mtproxy_attempts.csv"
    with attempts_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "time",
                "line_start",
                "line_end",
                "connection",
                "endpoint",
                "profile",
                "profile_id",
                "secret_kind",
                "hello_bytes",
                "client_hello_bytes",
                "verdict",
                "connection_type",
                "priority",
                "tcp_ms",
                "hmac_ms",
                "app_recv_ms",
                "disconnect_reason",
                "disconnect_error",
                "events",
            ],
        )
        writer.writeheader()
        for attempt in attempts:
            writer.writerow(
                {
                    "time": attempt.first_time,
                    "line_start": attempt.first_line,
                    "line_end": attempt.last_line,
                    "connection": attempt.key,
                    "endpoint": attempt.endpoint_text(),
                    "profile": profile_text(attempt),
                    "profile_id": attempt.profile_id,
                    "secret_kind": attempt.secret_kind,
                    "hello_bytes": attempt.hello_bytes,
                    "client_hello_bytes": attempt.client_hello_bytes,
                    "verdict": attempt.verdict(),
                    "connection_type": attempt.connection_type,
                    "priority": attempt.priority,
                    "tcp_ms": attempt.timing_ms("socket_connect_start", "socket_connected"),
                    "hmac_ms": attempt.timing_ms("client_hello_sent", "server_hello_hmac_ok"),
                    "app_recv_ms": attempt.timing_ms("first_tls_app_sent", "first_tls_app_recv"),
                    "disconnect_reason": attempt.disconnect_reason,
                    "disconnect_error": attempt.disconnect_error,
                    "events": ",".join(sorted(attempt.events)),
                }
            )

    by_endpoint_profile: defaultdict[tuple[str, str], list[Attempt]] = defaultdict(list)
    for attempt in attempts:
        by_endpoint_profile[(attempt.endpoint_text(), profile_text(attempt))].append(attempt)

    stats_path = out_dir / "mtproxy_endpoint_profile_stats.csv"
    verdict_columns = sorted({attempt.verdict() for attempt in attempts} | FAKETLS_FAILURE_VERDICTS | {"ok"})
    with stats_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "endpoint",
            "profile",
            "total",
            "ok",
            "ok_percent",
            "hmac_min_ms",
            "hmac_p50_ms",
            "hmac_max_ms",
            "max_1s",
            "max_5s",
            "top_failures",
            *verdict_columns,
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for (endpoint, profile), items in sorted(
            by_endpoint_profile.items(),
            key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
        ):
            verdicts = Counter(item.verdict() for item in items)
            hmac_values = [
                int(value)
                for item in items
                if (value := item.timing_ms("client_hello_sent", "server_hello_hmac_ok"))
            ]
            row = {
                "endpoint": endpoint,
                "profile": profile,
                "total": len(items),
                "ok": verdicts["ok"],
                "ok_percent": ok_percent(verdicts["ok"], len(items)),
                "hmac_min_ms": percentile(hmac_values, 0),
                "hmac_p50_ms": percentile(hmac_values, 50),
                "hmac_max_ms": percentile(hmac_values, 100),
                "max_1s": max_attempts_in_window(items, 1.0),
                "max_5s": max_attempts_in_window(items, 5.0),
                "top_failures": top_failures(verdicts),
            }
            for verdict in verdict_columns:
                row[verdict] = verdicts[verdict]
            writer.writerow(row)

    plain_rows: defaultdict[tuple[str, str, str, str, str], Counter[str]] = defaultdict(Counter)
    for attempt in all_attempts:
        if not attempt.secret_kind or attempt.secret_kind == "ee" or attempt.events["client_hello_sent"]:
            continue
        key = (
            attempt.endpoint_text(),
            attempt.secret_kind,
            attempt.account or "unknown",
            attempt.dc or "unknown",
            attempt.connection_type or "unknown",
        )
        stats = plain_rows[key]
        stats["connected"] += 1 if attempt.events["on_connected"] or attempt.events["account_connected"] else 0
        stats["send"] += attempt.events["account_send_message"]
        stats["recv"] += attempt.events["account_received_message"]
        stats["rpc_result"] += attempt.events["account_rpc_result"]
        stats["invalid_packet_length"] += attempt.events["account_invalid_packet_length"]
        stats["auth_404"] += attempt.events["account_auth_404"]
        for event, count in attempt.events.items():
            if event.startswith("account_disconnect_"):
                stats[event.replace("account_", "")] += count

    plain_path = out_dir / "mtproxy_plain_account_stats.csv"
    with plain_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "endpoint",
            "secret_kind",
            "account",
            "dc",
            "connection_type",
            "connected",
            "send",
            "recv",
            "rpc_result",
            "invalid_packet_length",
            "auth_404",
            "disconnect_0",
            "disconnect_1",
            "disconnect_2",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for (endpoint, secret_kind, account, dc, connection_type), stats in sorted(
            plain_rows.items(),
            key=lambda item: (-item[1]["send"], item[0]),
        ):
            writer.writerow(
                {
                    "endpoint": endpoint,
                    "secret_kind": secret_kind,
                    "account": account,
                    "dc": dc,
                    "connection_type": connection_type,
                    "connected": stats["connected"],
                    "send": stats["send"],
                    "recv": stats["recv"],
                    "rpc_result": stats["rpc_result"],
                    "invalid_packet_length": stats["invalid_packet_length"],
                    "auth_404": stats["auth_404"],
                    "disconnect_0": stats["disconnect_0"],
                    "disconnect_1": stats["disconnect_1"],
                    "disconnect_2": stats["disconnect_2"],
                }
            )


def print_report(attempts: list[Attempt], global_lines: list[str]) -> None:
    print("MTProxy FakeTLS diagnostic summary")
    print("===================================")
    if not attempts and not global_lines:
        print("No MTProxy markers found.")
        print("Most likely causes: APK was built without LOGS_ENABLED, wrong package was captured, or the MTProxy path was not exercised.")
        return

    verdicts = Counter(attempt.verdict() for attempt in attempts)
    profiles = Counter(profile_text(attempt) for attempt in attempts)
    print(f"Attempts: {len(attempts)}")
    print(f"FakeTLS attempts: {sum(1 for attempt in attempts if attempt.is_faketls())}")
    print("Verdicts:")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict}: {count}")
    print("Profiles:")
    for profile, count in profiles.most_common():
        print(f"  {profile}: {count}")

    if global_lines:
        print(f"Global/non-connection markers: {len(global_lines)}")

    print_faketls_reliability_summary(attempts)
    print_faketls_profile_summary(attempts)
    print_faketls_endpoint_summary(attempts)
    print_faketls_failure_timeline(attempts)
    print_plain_mtproxy_summary(attempts)

    all_lines = list(global_lines)
    for attempt in attempts:
        all_lines.extend(attempt.lines)
    print_proxy_check_summary(all_lines)

    print()
    print("Per-attempt details:")
    for attempt in attempts:
        endpoint = f" {attempt.endpoint_text()}"
        flags = ",".join(sorted(attempt.events)) or "no_known_phase"
        extra = []
        if attempt.hello_bytes:
            extra.append(f"hello={attempt.hello_bytes}")
        if attempt.connection_type:
            extra.append(f"type={attempt.connection_type}")
        if attempt.priority:
            extra.append(f"priority={attempt.priority}")
        if attempt.telegram_endpoint:
            extra.append(f"telegram={attempt.telegram_endpoint}")
        suffix = f" {' '.join(extra)}" if extra else ""
        print(f"- {attempt.key}{endpoint} profile={profile_text(attempt)} verdict={attempt.verdict()}{suffix}")
        print(f"  lines={attempt.first_line}-{attempt.last_line} events={flags}")
        if attempt.disconnect:
            print(f"  disconnect={attempt.disconnect}")

    print()
    print("How to read the verdicts:")
    print("- tcp_not_connected: TCP/connect/IP/proxy availability layer.")
    print("- connected_without_socket_connected_marker: Telegram reached on_connected, but this log slice has no socket_connected marker; do not treat it as a TCP failure.")
    print("- client_hello_sent_no_server_hello: compare VPN vs non-VPN; with VPN failure points to server/client compatibility, without VPN it can be DPI blackhole.")
    print("- server_hello_hmac_mismatch: likely ClientHello/profile/server response mismatch, not plain packet loss.")
    print("- post_handshake_no_appdata: HMAC passed; inspect TLS app-data write/read path and first MTProto packets.")
    print("- dropped_after_appdata: startup worked; look at later MTProto keepalive, server close, or external throttling.")
    print("- proxy_check fail:tcp_not_connected: TCP/connect/DNS/server availability layer; compare with VPN and external probe.")
    print("- proxy_check fail:tcp_connected_no_pong: TCP opened, but MTProxy ping did not complete; can be dead proxy, server overload, or path filtering.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("markers", type=Path, help="Path to mtproxy_markers.txt")
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Optional directory for CSV reports: mtproxy_attempts.csv and mtproxy_endpoint_profile_stats.csv",
    )
    args = parser.parse_args()

    if not args.markers.exists():
        raise SystemExit(f"markers file not found: {args.markers}")

    attempts, global_lines = load_attempts(args.markers)
    print_report(attempts, global_lines)
    if args.out_dir:
        write_csv_reports(attempts, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
