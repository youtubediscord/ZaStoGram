#!/usr/bin/env python3
from pathlib import Path
import csv
import re
import subprocess
import sys
import tempfile

from analyze_mtproxy_markers import Attempt


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"
SOCKET = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
DIAGNOSTICS = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckDiagnostics.java"


def require(condition, message):
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def check_phase_contract():
    socket = SOCKET.read_text(encoding="utf-8", errors="replace")
    analyzer = ANALYZER.read_text(encoding="utf-8", errors="replace")
    diagnostics = DIAGNOSTICS.read_text(encoding="utf-8", errors="replace")

    diagnostic_values = set(re.findall(r'public static final String [A-Z0-9_]+ = "([a-z0-9_]+)";', diagnostics))
    native_published = set(re.findall(r'publishProxyConnectionStage\("([a-z0-9_]+)"\)', socket))
    native_terminal = set(re.findall(r'proxyCheckDiagnostic = "([a-z0-9_]+)";', socket))
    mtproxy_terminal = native_terminal - {"wss_tls_handshake"}

    require(
        not (native_published - diagnostic_values),
        f"Java proxy diagnostics must know every native-published MTProxy phase: {sorted(native_published - diagnostic_values)}",
    )
    require(
        not (mtproxy_terminal - diagnostic_values),
        f"Java proxy diagnostics must know every native MTProxy terminal phase: {sorted(mtproxy_terminal - diagnostic_values)}",
    )
    require(
        "wss_tls_handshake" not in diagnostic_values,
        "WSS TLS handshake is a WSS diagnostic and must not be mixed into the MTProxy GUI diagnostic map",
    )
    missing_analyzer = sorted(phase for phase in native_published | mtproxy_terminal if phase not in analyzer)
    require(
        not missing_analyzer,
        f"MTProxy analyzer must know every native MTProxy phase used by GUI/logs: {missing_analyzer}",
    )
    event_map_start = analyzer.find("event_map = {")
    event_map_end = analyzer.find("\n        for needle, event in event_map.items():", event_map_start)
    event_map = analyzer[event_map_start:event_map_end]
    missing_event_map = sorted(phase for phase in native_published | mtproxy_terminal if phase not in event_map)
    require(
        not missing_event_map,
        f"MTProxy analyzer event_map must classify every native-published or terminal phase, not merely mention it elsewhere: {missing_event_map}",
    )
    require(
        "def event_marker_matches" in analyzer
        and "if event_marker_matches(text, needle):" in analyzer
        and "if needle in text:" not in event_map,
        "MTProxy analyzer must match event markers as standalone tokens, not by raw substring",
    )
    native_startup_markers = set(re.findall(r"mtproxy_startup ([a-zA-Z0-9_]+)", socket))
    directly_handled_markers = {
        "close_diagnostic",
        "close_diagnostic_suppressed",
        "profile",
    }
    missing_startup_markers = sorted(
        marker for marker in native_startup_markers
        if marker not in event_map and marker not in directly_handled_markers
    )
    require(
        not missing_startup_markers,
        f"MTProxy analyzer must preserve every native mtproxy_startup marker or mark it as directly handled: {missing_startup_markers}",
    )


def main():
    check_phase_contract()

    def events_for_line(line):
        attempt = Attempt(key="event-overlap")
        attempt.add(1, line)
        return {key: value for key, value in attempt.events.items() if value}

    overlap_cases = [
        (
            "connection(0x1) mtproxy_startup admission_grant_queued admission_mode=strict key=x",
            {"admission_grant_queued": 1},
        ),
        (
            "connection(0x1) mtproxy_startup admission_dequeue_global admission_mode=strict key=x",
            {"admission_dequeue_global": 1},
        ),
        (
            "connection(0x1) mtproxy_startup admission_release_ignored admission_mode=strict key=x",
            {"admission_release_ignored": 1},
        ),
        (
            "connection(0x1) mtproxy_startup tcp_connect_gate_release key=x active=0 reason=closeSocket",
            {"tcp_connect_gate_release": 1},
        ),
        (
            "connection(0x1) mtproxy_startup tcp_connect_gate_wait key=x active=1 delay=100 ready=0",
            {"tcp_connect_gate_wait": 1},
        ),
        (
            "connection(0x1) mtproxy_startup admission_queue_wait admission_mode=strict key=x",
            {"admission_queue_wait": 1},
        ),
    ]
    for line, expected_events in overlap_cases:
        require(
            events_for_line(line) == expected_events,
            f"analyzer must not double-count nested mtproxy_startup markers in line: {line}",
        )

    digit_profile = Attempt(key="digit-profile")
    digit_profile.add(
        1,
        "connection(0x1) mtproxy_startup profile selected=android11_okhttp_advisory id=5 mode=auto hello=1234",
    )
    require(
        digit_profile.profile == "android11_okhttp_advisory"
        and digit_profile.profile_id == "5"
        and digit_profile.hello_bytes == "1234",
        "analyzer profile parser must preserve profile names with digits plus id and hello size",
    )
    digit_connect = Attempt(key="digit-connect")
    digit_connect.add(
        1,
        "connection(0x1) mtproxy_startup connect_start proxy_state=10 secret_kind=ee is_faketls=1 "
        "domain_len=1 profile=android11_okhttp_advisory connection_pattern=strict address=1.2.3.4 port=443",
    )
    require(
        digit_connect.profile == "android11_okhttp_advisory"
        and digit_connect.address == "1.2.3.4"
        and digit_connect.port == "443",
        "analyzer connect_start parser must preserve profile names with digits",
    )
    delayed_priority = Attempt(key="delayed-priority")
    delayed_priority.add(
        1,
        "connection(0x1) mtproxy_startup admission_dequeue admission_mode=strict connection_pattern=strict "
        "key=1.2.3.4:443:cdn.example active=1 queued=0 priority=20",
    )
    require(
        delayed_priority.proxy_key == "1.2.3.4:443:cdn.example"
        and delayed_priority.endpoint == "1.2.3.4:443"
        and delayed_priority.priority == "20",
        "analyzer admission parser must preserve priority even when it is not immediately after key",
    )
    endpoint_key = Attempt(key="endpoint-key")
    endpoint_key.add(
        1,
        "connection(0x1) mtproxy_startup endpoint_cooldown key=1.2.3.4:443:cdn.example "
        "connection_pattern=strict priority=20 delay=100 cooldown_ms=5000",
    )
    require(
        endpoint_key.proxy_key == "1.2.3.4:443:cdn.example"
        and endpoint_key.endpoint == "1.2.3.4:443"
        and endpoint_key.priority == "20",
        "analyzer must preserve endpoint keys outside admission_* markers",
    )
    network_key = Attempt(key="network-key")
    network_key.add(
        1,
        "connection(0x1) mtproxy_startup tcp_connect_gate key=1.2.3.4:443 active=1 delay=100 ready=0",
    )
    require(
        network_key.proxy_key == "1.2.3.4:443"
        and network_key.endpoint == "1.2.3.4:443",
        "analyzer must preserve network endpoint keys from TCP gate markers",
    )
    ipv6_network_key = Attempt(key="ipv6-network-key")
    ipv6_network_key.add(
        1,
        "connection(0x1) mtproxy_startup endpoint_failure key=2001:db8::1:443 "
        "phase=tcp_not_connected reason=closeSocket connection_pattern=strict priority=20 cooldown_ms=5200 recipe_level=1",
    )
    require(
        ipv6_network_key.proxy_key == "2001:db8::1:443"
        and ipv6_network_key.endpoint == "2001:db8::1:443",
        "analyzer must not strip the port from IPv6 network endpoint keys without SNI",
    )

    attempt = Attempt(key="synthetic")
    attempt.add(1, "connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0")
    attempt.add(2, "connection(0x1) mtproxy_startup on_connected tls=0")
    require(
        attempt.verdict() == "connected_without_socket_connected_marker",
        "an attempt that reached on_connected must not be reported as tcp_not_connected",
    )

    suppressed_drop = Attempt(key="suppressed-drop")
    suppressed_drop.add(1, "connection(0x11) mtproxy_startup socket_connect_start ipv6=0 state=10")
    suppressed_drop.add(2, "connection(0x11) mtproxy_startup socket_connected elapsed=70")
    suppressed_drop.add(3, "connection(0x11) mtproxy_startup client_hello_sent bytes=1897")
    suppressed_drop.add(4, "connection(0x11) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0")
    suppressed_drop.add(5, "connection(0x11) mtproxy_startup on_connected tls=1")
    suppressed_drop.add(6, "connection(0x11) mtproxy_startup first_tls_app_recv payload=105")
    suppressed_drop.add(
        7,
        "connection(0x11) mtproxy_startup close_diagnostic_suppressed "
        "phase=dropped_after_appdata reason=peer_closed first_tls_sent=1 first_tls_recv=1 first_plain_sent=0 first_plain_recv=0",
    )
    require(
        suppressed_drop.verdict() == "ok",
        "suppressed close diagnostics after first app-data must not turn a usable connection into a drop",
    )

    idle_after_handshake = Attempt(key="idle-after-handshake")
    idle_after_handshake.add(1, "connection(0x12) mtproxy_startup socket_connect_start ipv6=0 state=10")
    idle_after_handshake.add(2, "connection(0x12) mtproxy_startup socket_connected elapsed=70")
    idle_after_handshake.add(3, "connection(0x12) mtproxy_startup client_hello_sent bytes=1897")
    idle_after_handshake.add(4, "connection(0x12) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0")
    idle_after_handshake.add(5, "connection(0x12) mtproxy_startup on_connected tls=1")
    idle_after_handshake.add(
        6,
        "connection(0x12) mtproxy_startup close_diagnostic_suppressed "
        "phase=post_handshake_no_appdata reason=peer_closed first_tls_sent=0 first_tls_recv=0 first_plain_sent=0 first_plain_recv=0",
    )
    require(
        idle_after_handshake.verdict() == "handshake_ok_no_appdata_sent",
        "idle post-handshake sockets that never sent app-data must not be reported as post_handshake_no_appdata",
    )

    tls_appdata_timeout = Attempt(key="tls-appdata-timeout")
    tls_appdata_timeout.add(1, "connection(0x15) mtproxy_startup socket_connect_start ipv6=0 state=10")
    tls_appdata_timeout.add(2, "connection(0x15) mtproxy_startup socket_connected elapsed=70")
    tls_appdata_timeout.add(3, "connection(0x15) mtproxy_startup client_hello_sent bytes=1897")
    tls_appdata_timeout.add(4, "connection(0x15) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0")
    tls_appdata_timeout.add(5, "connection(0x15) mtproxy_startup on_connected tls=1")
    tls_appdata_timeout.add(6, "connection(0x15) mtproxy_startup mtproxy_tls_appdata_no_response_timeout elapsed=5601")
    require(
        tls_appdata_timeout.verdict() == "post_handshake_no_appdata",
        "FakeTLS app-data no-response timeout must be classified as post_handshake_no_appdata even if earlier first_tls_app_sent logs were truncated",
    )

    tcp_connected_no_pong = Attempt(key="tcp-connected-no-pong")
    tcp_connected_no_pong.add(1, "connection(0x16) mtproxy_startup socket_connect_start ipv6=0 state=10")
    tcp_connected_no_pong.add(2, "connection(0x16) mtproxy_startup socket_connected elapsed=70")
    tcp_connected_no_pong.add(3, "connection(0x16) mtproxy_startup close_diagnostic phase=tcp_connected_no_pong")
    require(
        tcp_connected_no_pong.verdict() == "tcp_connected_no_pong",
        "direct native tcp_connected_no_pong diagnostics must not be hidden as a generic pre-ClientHello failure",
    )

    hmac_mismatch_direct = Attempt(key="hmac-mismatch-direct")
    hmac_mismatch_direct.add(1, "connection(0x17) mtproxy_startup socket_connect_start ipv6=0 state=10")
    hmac_mismatch_direct.add(2, "connection(0x17) mtproxy_startup socket_connected elapsed=70")
    hmac_mismatch_direct.add(3, "connection(0x17) mtproxy_startup client_hello_sent bytes=1897")
    hmac_mismatch_direct.add(4, "connection(0x17) mtproxy_startup close_diagnostic phase=server_hello_hmac_mismatch")
    require(
        hmac_mismatch_direct.verdict() == "server_hello_hmac_mismatch",
        "direct native server_hello_hmac_mismatch diagnostics must be classified even without a separate timeout marker",
    )

    reused_pointer_latency = Attempt(key="reused-pointer-latency")
    reused_pointer_latency.add(
        1,
        "06-20 15:00:02.000 connection(0x13) mtproxy_startup client_hello_sent bytes=1897",
    )
    reused_pointer_latency.add(
        2,
        "06-20 15:00:01.900 connection(0x13) mtproxy_startup server_hello_hmac_ok bytes=2219",
    )
    require(
        reused_pointer_latency.timing_ms("client_hello_sent", "server_hello_hmac_ok") == "",
        "analyzer must ignore negative event latency caused by reused pointers or out-of-order marker grouping",
    )

    tcp_gate_wait = Attempt(key="tcp-gate-wait")
    tcp_gate_wait.add(
        1,
        "06-20 15:00:02.000 connection(0x14) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.14 port=443",
    )
    tcp_gate_wait.add(2, "connection(0x14) mtproxy_startup tcp_connect_gate key=198.51.100.14:443 active=1 delay=650 ready=0")
    tcp_gate_wait.add(3, "connection(0x14) mtproxy_startup tcp_connect_gate_wait key=198.51.100.14:443 active=1 delay=2300 ready=1")
    require(
        tcp_gate_wait.verdict() == "tcp_connect_gate_timeout",
        "an analyzer attempt that never started TCP because it waited in the TCP gate must be a terminal gate timeout",
    )

    admission_wait = Attempt(key="admission-wait")
    admission_wait.add(
        1,
        "06-20 15:00:02.000 connection(0x15) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.15 port=443",
    )
    admission_wait.add(2, "connection(0x15) mtproxy_startup admission_queue admission_mode=browser connection_pattern=browser key=198.51.100.15:443:cdn.example priority=0 active=1 limit=1 global_active=1 global_limit=1 queued=1 cooldown_ms=0 retry=650")
    admission_wait.add(3, "connection(0x15) mtproxy_startup admission_queue_wait admission_mode=browser connection_pattern=browser key=198.51.100.15:443:cdn.example priority=0 active=1 limit=1 global_active=1 global_limit=1 queued=1 cooldown_ms=0 retry=650")
    require(
        admission_wait.verdict() == "admission_timeout",
        "an analyzer attempt that only waited in admission queue must be a terminal admission timeout",
    )
    pre_tcp_overlap = Attempt(key="pre-tcp-gate-admission-overlap")
    pre_tcp_overlap.add(
        1,
        "06-20 15:00:02.000 connection(0x18) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.18 port=443",
    )
    pre_tcp_overlap.add(2, "connection(0x18) mtproxy_startup tcp_connect_gate_grant key=198.51.100.18:443 active=1 ready=1")
    pre_tcp_overlap.add(3, "connection(0x18) mtproxy_startup admission_queue admission_mode=browser connection_pattern=browser key=198.51.100.18:443:cdn.example priority=0 active=1 limit=1 global_active=1 global_limit=1 queued=1 cooldown_ms=0 retry=650")
    pre_tcp_overlap.add(4, "connection(0x18) mtproxy_startup close_diagnostic phase=tcp_not_connected")
    require(
        pre_tcp_overlap.verdict() == "pre_tcp_gate_admission_overlap",
        "old logs with TCP gate held while admission queued must be flagged as an architecture overlap, not generic tcp_not_connected",
    )
    admission_pending_host = Attempt(key="admission-pending-host")
    admission_pending_host.add(
        1,
        "06-20 15:00:02.000 connection(0x19) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.19 port=443",
    )
    admission_pending_host.add(
        2,
        "connection(0x19) mtproxy_transport host_resolve_state_change waiting=1 "
        "reason=host_resolve_pending waiting_resolve=1 host_len=18 transport_state=prepared",
    )
    admission_pending_host.add(
        3,
        "connection(0x19) mtproxy_startup admission_queue admission_mode=browser "
        "connection_pattern=browser key=198.51.100.19:443:cdn.example priority=0 active=1 limit=1 queued=1 retry=650",
    )
    require(
        admission_pending_host.verdict() == "admission_timeout",
        "pending host without real host_resolve_start must stay admission_timeout, not host_resolve_failed/timeout",
    )

    endpoint_cooldown = Attempt(key="endpoint-cooldown-timeout")
    endpoint_cooldown.add(
        1,
        "06-20 15:00:02.000 connection(0x20) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.20 port=443",
    )
    endpoint_cooldown.add(2, "connection(0x20) mtproxy_startup endpoint_cooldown key=198.51.100.20:443 delay=3500 cooldown_ms=3500")
    require(
        endpoint_cooldown.verdict() == "endpoint_cooldown_timeout",
        "endpoint cooldown wait without socket_connect_start must be endpoint_cooldown_timeout",
    )

    dns_coalesce = Attempt(key="dns-coalesce-timeout")
    dns_coalesce.add(
        1,
        "06-20 15:00:02.000 connection(0x21) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.21 port=443",
    )
    dns_coalesce.add(2, "connection(0x21) mtproxy_startup dns_coalesce_wait dns_key=198.51.100.21:443 delay=750")
    require(
        dns_coalesce.verdict() == "dns_coalesce_timeout",
        "DNS coalesce wait without socket_connect_start must be dns_coalesce_timeout",
    )

    host_resolve_timeout = Attempt(key="host-resolve-timeout")
    host_resolve_timeout.add(
        1,
        "06-20 15:00:02.000 connection(0x22) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.22 port=443",
    )
    host_resolve_timeout.add(2, "connection(0x22) mtproxy_startup host_resolve_start host=blocked.example key=198.51.100.22:443:cdn.example")
    require(
        host_resolve_timeout.verdict() == "host_resolve_timeout",
        "real host_resolve_start without callback/socket_connect_start must be host_resolve_timeout",
    )

    real_tcp_failure = Attempt(key="real-tcp-failure")
    real_tcp_failure.add(
        1,
        "06-20 15:00:02.000 connection(0x23) mtproxy_startup connect_start proxy_state=10 "
        "secret_kind=ee is_faketls=1 domain_len=17 profile=firefox_android "
        "connection_pattern=browser address=198.51.100.23 port=443",
    )
    real_tcp_failure.add(2, "connection(0x23) mtproxy_startup socket_connect_start ipv6=0 state=10")
    require(
        real_tcp_failure.verdict() == "tcp_not_connected",
        "socket_connect_start without socket_connected must remain tcp_not_connected",
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        marker_path = Path(handle.name)
        handle.write("logcat.txt:1: connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0\n")
        handle.write("logcat.txt:2: connection(0x1) mtproxy_startup on_connected tls=0\n")
        handle.write(
            "logcat.txt:3: 06-20 15:00:00.000 connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=203.0.113.10 port=443\n"
        )
        handle.write(
            "logcat.txt:3: 06-20 15:00:00.010 connection(0x2) mtproxy_startup admission_queue "
            "admission_mode=strict connection_pattern=strict key=blocked.example:443:cdn.example "
            "priority=20 active=1 max=1 queued=1\n"
        )
        handle.write("logcat.txt:4: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:5: connection(0x2) mtproxy_startup socket_connected elapsed=90\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup client_hello_fragment_plan mode=soft total=1897 first=517 fragments=3\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup client_hello_fragment mode=soft index=1 offset=517 total=1897 next_delay=88\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup server_data_before_client_hello_complete pending_hello=517/1897 read=128\n")
        handle.write(
            "logcat.txt:7: connection(0x2) mtproxy_startup admission_freeze_detected "
            "key=blocked.example:443:cdn.example elapsed=4500\n"
        )
        handle.write(
            "logcat.txt:7: connection(0x2) mtproxy_startup admission_hold_after_client_hello_failure "
            "admission_mode=strict connection_pattern=strict reason=freeze_timeout "
            "key=blocked.example:443:cdn.example queued=2 cooldown_ms=5200\n"
        )
        handle.write("logcat.txt:8: connection(0x2) mtproxy_startup server_hello_timeout_close elapsed=4500\n")
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.200 connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=203.0.113.10 port=443\n"
        )
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.200 connection(0x2) mtproxy_startup admission_grant "
            "admission_mode=strict connection_pattern=strict key=blocked.example:443:cdn.example priority=20 active=1 max=1\n"
        )
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.250 connection(0x2) mtproxy_startup admission_tcp_failure_cooldown "
            "admission_mode=strict connection_pattern=strict reason=closeSocket key=blocked.example:443:cdn.example "
            "penalty=1 cooldown_ms=5200\n"
        )
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.260 connection(0x2) mtproxy_startup admission_freeze_cooldown "
            "admission_mode=strict connection_pattern=strict reason=closeSocket key=blocked.example:443:cdn.example "
            "penalty=1 cooldown_ms=6200\n"
        )
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.270 connection(0x2) mtproxy_startup admission_failure_cooldown "
            "admission_mode=strict connection_pattern=strict reason=closeSocket key=blocked.example:443:cdn.example "
            "penalty=1 cooldown_ms=4200\n"
        )
        handle.write("logcat.txt:10: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:11: connection(0x2) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:12: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:13: connection(0x2) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:14: connection(0x2) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:14: connection(0x2) mtproxy_data tls_frame_complete index=1 payload=96 frame=101 record_sizing=1 timing=1 startup_cover=1 more_data=1\n")
        handle.write("logcat.txt:15: connection(0x2) mtproxy_startup first_tls_app_recv payload=105\n")
        handle.write("logcat.txt:15: connection(0x2) mtproxy_disconnect reason=2 reason_text=peer_closed error=0 error_text=ok secret_kind=ee is_faketls=1 is_wss=0 proxy_state=0 tls_state=0 bytes_read=512 pending_hello=0/0 pending=0/0 first_tls_sent=1 first_tls_recv=1 first_plain_sent=0 first_plain_recv=0 tls_frames_completed=3\n")
        handle.write("logcat.txt:15: proxy_connection_stage account=0 phase=client_hello_sent\n")
        handle.write("logcat.txt:15: proxy_connection_stage account=0 phase=server_hello_hmac_ok\n")
        handle.write(
            "logcat.txt:15: 06-20 15:00:01.000 connection(0x5) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=198.51.100.55 port=443\n"
        )
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup first_tls_app_recv payload=105\n")
        handle.write("logcat.txt:15: connection(0x5) mtproxy_startup close_diagnostic phase=dropped_early_after_appdata\n")
        handle.write(
            "logcat.txt:15: 06-20 15:00:01.200 connection(0x7) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=198.51.100.77 port=443\n"
        )
        handle.write("logcat.txt:15: connection(0x7) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:15: connection(0x7) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:15: connection(0x7) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:15: connection(0x7) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:15: connection(0x7) mtproxy_startup on_connected tls=1\n")
        handle.write(
            "logcat.txt:15: connection(0x7) mtproxy_startup close_diagnostic_suppressed "
            "phase=post_handshake_no_appdata reason=peer_closed first_tls_sent=0 first_tls_recv=0 first_plain_sent=0 first_plain_recv=0\n"
        )
        handle.write(
            "logcat.txt:15: 06-20 15:00:01.300 connection(0x8) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=198.51.100.88 port=443\n"
        )
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:15: connection(0x8) mtproxy_startup first_tls_app_recv payload=105\n")
        handle.write(
            "logcat.txt:15: connection(0x8) mtproxy_startup close_diagnostic_suppressed "
            "phase=dropped_after_appdata reason=peer_closed first_tls_sent=1 first_tls_recv=1 first_plain_sent=0 first_plain_recv=0\n"
        )
        handle.write(
            "logcat.txt:15: 06-20 15:00:01.400 connection(0x9) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=198.51.100.99 port=443\n"
        )
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup first_tls_app_recv payload=105\n")
        handle.write("logcat.txt:15: connection(0x9) mtproxy_startup close_diagnostic phase=dropped_after_appdata\n")
        handle.write(
            "logcat.txt:15: 06-20 15:00:01.500 connection(0x6) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome connection_pattern=strict address=198.51.100.66 port=443\n"
        )
        handle.write("logcat.txt:15: connection(0x6) mtproxy_startup resolved_sslip host=198.51.100.66.sslip.io address=198.51.100.66\n")
        handle.write("logcat.txt:15: connection(0x6) mtproxy_startup endpoint_failure key=198.51.100.66:443 phase=tcp_not_connected reason=closeSocket connection_pattern=strict priority=0 cooldown_ms=5200 recipe_level=1\n")
        handle.write("logcat.txt:15: connection(0x6) mtproxy_startup endpoint_handshake_ok network_key=198.51.100.66:443 key=198.51.100.66:443:cdn.example reason=server_hello_hmac_ok\n")
        handle.write("logcat.txt:15: connection(0x6) mtproxy_startup endpoint_data_path_success network_key=198.51.100.66:443 key=198.51.100.66:443:cdn.example reason=first_tls_app_recv\n")
        handle.write("logcat.txt:15: connection(0x6) mtproxy_startup host_resolve_failed host=blocked-dns.example reason=no_delegate\n")
        handle.write(
            "logcat.txt:16: proxy_check_start state=ping_sent ping_id=1 request_token=1 "
            "address=dead.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:17: proxy_check_connection_closed close_reason=2 ping_id=1 request_token=1 connection_num=0 state=1\n")
        handle.write(
            "logcat.txt:18: proxy_check_finish result=fail reason=connection_closed request_found=1 "
            "ping_id=1 address=dead.example:443 connection_num=0 state=finished\n"
        )
        handle.write(
            "logcat.txt:19: proxy_check_start state=ping_sent ping_id=2 request_token=2 "
            "address=frozen.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:20: proxy_check_socket_connected ping_id=2 request_token=2 connection_num=0 connection_token=2\n")
        handle.write("logcat.txt:21: proxy_check_connection_closed close_reason=2 ping_id=2 request_token=2 connection_num=0 state=1\n")
        handle.write(
            "logcat.txt:22: proxy_check_finish result=fail reason=connection_closed request_found=1 "
            "ping_id=2 address=frozen.example:443 connection_num=0 state=finished\n"
        )
        handle.write(
            "logcat.txt:23: proxy_check_start state=ping_sent ping_id=3 request_token=3 "
            "address=ok.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:24: proxy_check_socket_connected ping_id=3 request_token=3 connection_num=0 connection_token=3\n")
        handle.write(
            "logcat.txt:25: proxy_check_finish result=ok reason=pong request_found=1 "
            "ping_id=3 address=ok.example:443 connection_num=0 state=finished\n"
        )
        handle.write("logcat.txt:25: proxy_check_scheduler enqueue endpoint=dead.example:443 queued=1\n")
        handle.write("logcat.txt:25: proxy_check_scheduler start endpoint=dead.example:443 queued=0\n")
        handle.write(
            "logcat.txt:25: proxy_check_scheduler finish result=fail "
            "raw_endpoint=wrong.example:443 raw_phase=stale_raw raw_diagnostic=stale_raw "
            "phase=tcp_not_connected diagnostic=network_block_suspected time=-1 applied_time=-1 raw_time=-1 "
            "endpoint=dead.example:443 queued=0 cancelled=false listeners=1\n"
        )
        handle.write(
            "logcat.txt:25: proxy_check_scheduler backoff endpoint=dead.example:443 "
            "wait_ms=120000 failures=2 raw_phase=stale_raw phase=network_block_suspected source=proxy_check\n"
        )
        handle.write(
            "logcat.txt:25: proxy_check_scheduler skip_backoff endpoint=dead.example:443 "
            "wait_ms=119000 phase=network_block_suspected\n"
        )
        handle.write("logcat.txt:25: proxy_check_scheduler finish_keep_connected endpoint=ok.example:443\n")
        handle.write(
            "logcat.txt:26: 06-20 15:00:02.000 connection(0x3, account0, dc2, type 1) connecting "
            "(149.154.167.51:443)\n"
        )
        handle.write(
            "logcat.txt:27: connection(0x3) connecting via proxy plain.example:443 "
            "secret[17] secret_kind=dd\n"
        )
        handle.write(
            "logcat.txt:28: 06-20 15:00:02.050 connection(0x3) mtproxy_startup connect_start proxy_state=0 "
            "secret_kind=dd is_faketls=0 domain_len=0 profile=android_chrome address=149.154.167.51 port=443\n"
        )
        handle.write("logcat.txt:28: connection(0x3) mtproxy_startup socket_connected state=0 tls=0 secret_kind=dd\n")
        handle.write("logcat.txt:29: connection(0x3) mtproxy_startup on_connected tls=0\n")
        handle.write("logcat.txt:30: connection(0x3) mtproxy_startup first_mtproxy_packet_sent bytes=128 secret_kind=dd\n")
        handle.write("logcat.txt:31: connection(0x3, account0, dc2, type 1) send message invokeWithLayer\n")
        handle.write("logcat.txt:32: connection(0x3) mtproxy_startup first_mtproxy_packet_recv bytes=98 secret_kind=dd\n")
        handle.write("logcat.txt:33: connection(0x3, account0, dc2, type 1) received message len 98\n")
        handle.write("logcat.txt:32: connection(0x3, account0, dc2, type 1) received object TL_rpc_result\n")
        handle.write("logcat.txt:33: connection(0x3, account0, dc2, type 1) received rpc_result with TL_boolTrue\n")
        handle.write(
            "logcat.txt:34: 06-20 15:00:03.000 connection(0x4, account0, dc2, type 2) connecting "
            "(149.154.167.51:443)\n"
        )
        handle.write(
            "logcat.txt:35: connection(0x4) connecting via proxy plain.example:443 "
            "secret[17] secret_kind=dd\n"
        )
        handle.write(
            "logcat.txt:36: 06-20 15:00:03.050 connection(0x4) mtproxy_startup connect_start proxy_state=0 "
            "secret_kind=dd is_faketls=0 domain_len=0 profile=android_chrome address=149.154.167.51 port=443\n"
        )
        handle.write("logcat.txt:36: connection(0x4) mtproxy_startup socket_connected state=0 tls=0 secret_kind=dd\n")
        handle.write("logcat.txt:37: connection(0x4) mtproxy_startup on_connected tls=0\n")
        handle.write("logcat.txt:38: connection(0x4) mtproxy_startup first_mtproxy_packet_sent bytes=96 secret_kind=dd\n")
        handle.write("logcat.txt:39: connection(0x4, account0, dc2, type 2) send message getFile\n")
        handle.write("logcat.txt:39: connection(0x4, account0, dc2, type 2) reset auth key due to -404 error\n")
        handle.write("logcat.txt:40: connection(0x4, account0, dc2, type 2) received invalid packet length\n")
        handle.write("logcat.txt:40: connection(0x4) mtproxy_startup close_diagnostic phase=mtproxy_packet_sent_no_response\n")
        handle.write("logcat.txt:41: connection(0x4, account0, dc2, type 2) disconnected with reason 2\n")
    try:
        with tempfile.TemporaryDirectory() as csv_dir:
            result = subprocess.run(
                [sys.executable, str(ANALYZER), str(marker_path), "--out-dir", csv_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            attempts_csv = Path(csv_dir) / "mtproxy_attempts.csv"
            endpoint_csv = Path(csv_dir) / "mtproxy_endpoint_profile_stats.csv"
            proxy_check_csv = Path(csv_dir) / "mtproxy_proxy_check_stats.csv"
            scheduler_csv = Path(csv_dir) / "mtproxy_scheduler_stats.csv"
            require(attempts_csv.exists(), "analyzer must write per-attempt CSV when --out-dir is passed")
            require(endpoint_csv.exists(), "analyzer must write endpoint/profile stats CSV when --out-dir is passed")
            require(proxy_check_csv.exists(), "analyzer must write proxy-check endpoint stats CSV when --out-dir is passed")
            require(scheduler_csv.exists(), "analyzer must write Java scheduler endpoint stats CSV when --out-dir is passed")
            endpoint_csv_text = endpoint_csv.read_text(encoding="utf-8")
            proxy_check_csv_text = proxy_check_csv.read_text(encoding="utf-8")
            scheduler_csv_text = scheduler_csv.read_text(encoding="utf-8")
            require(
                "blocked.example:443" in endpoint_csv_text,
                "endpoint/profile CSV must include FakeTLS endpoint names",
            )
            require(
                "early_drop" in endpoint_csv_text.splitlines()[0],
                "endpoint/profile CSV must expose early_drop as a compact aggregate column",
            )
            require(
                "tls_frames_completed" in endpoint_csv_text.splitlines()[0],
                "endpoint/profile CSV must expose completed FakeTLS record count for data-path diagnosis",
            )
            rows = list(csv.DictReader(endpoint_csv_text.splitlines()))
            blocked_row = next((row for row in rows if row["endpoint"] == "blocked.example:443" and row["profile"] == "android_chrome"), None)
            require(
                blocked_row is not None and blocked_row["tls_frames_completed"] == "3",
                "endpoint/profile CSV must prefer the final disconnect FakeTLS record count when per-frame markers are sampled",
            )
            early_drop_row = next((row for row in rows if row["endpoint"] == "198.51.100.55:443" and row["profile"] == "android_chrome"), None)
            require(
                early_drop_row is not None and early_drop_row["early_drop"] == "1",
                "endpoint/profile CSV must count early post-appdata drops in the compact early_drop column",
            )
            proxy_check_rows = list(csv.DictReader(proxy_check_csv_text.splitlines()))
            dead_proxy_row = next((row for row in proxy_check_rows if row["endpoint"] == "dead.example:443"), None)
            frozen_proxy_row = next((row for row in proxy_check_rows if row["endpoint"] == "frozen.example:443"), None)
            ok_proxy_row = next((row for row in proxy_check_rows if row["endpoint"] == "ok.example:443"), None)
            require(
                dead_proxy_row is not None and dead_proxy_row["tcp_not_connected"] == "1",
                "proxy-check CSV must expose endpoint TCP-open failures separately from FakeTLS attempts",
            )
            require(
                frozen_proxy_row is not None and frozen_proxy_row["tcp_connected_no_pong"] == "1",
                "proxy-check CSV must expose endpoint post-TCP/no-pong failures",
            )
            require(
                ok_proxy_row is not None and ok_proxy_row["ok"] == "1",
                "proxy-check CSV must expose endpoint pong successes",
            )
            scheduler_rows = list(csv.DictReader(scheduler_csv_text.splitlines()))
            dead_scheduler_row = next((row for row in scheduler_rows if row["endpoint"] == "dead.example:443"), None)
            ok_scheduler_row = next((row for row in scheduler_rows if row["endpoint"] == "ok.example:443"), None)
            require(
                dead_scheduler_row is not None
                and dead_scheduler_row["enqueue"] == "1"
                and dead_scheduler_row["start"] == "1"
                and dead_scheduler_row["finish_fail"] == "1"
                and dead_scheduler_row["backoff"] == "1"
                and dead_scheduler_row["skip_backoff"] == "1"
                and dead_scheduler_row["finish_phase_tcp_not_connected"] == "1"
                and dead_scheduler_row["diagnostic_network_block_suspected"] == "3",
                "scheduler CSV must expose finish phases and display diagnostics separately",
            )
            require(
                "phase_network_block_suspected" not in dead_scheduler_row
                and "phase_tcp_not_connected" not in dead_scheduler_row,
                "scheduler CSV must not mix finish phases and display diagnostics in phase_* columns",
            )
            require(
                ok_scheduler_row is not None and ok_scheduler_row["finish_keep_connected"] == "1",
                "scheduler CSV must expose preserved-connected outcomes separately from failures",
            )
    finally:
        marker_path.unlink(missing_ok=True)

    require(result.returncode == 0, result.stderr.strip() or "analyzer exited with failure")
    require(
        "connected_without_socket_connected_marker:" in result.stdout,
        "analyzer summary must expose connected attempts that are missing the socket_connected marker",
    )
    require(
        "tcp_not_connected: 1" not in result.stdout,
        "analyzer must not classify on_connected attempts as TCP failures",
    )
    require(
        "client_hello_sent_no_server_hello: 1" in result.stdout,
        "analyzer must classify a connected ClientHello timeout as a pre-ServerHello failure",
    )
    require(
        "dropped_early_after_appdata: 1" in result.stdout,
        "analyzer must classify quick drops after first app data as a distinct post-handshake endpoint/lifecycle phase",
    )
    require(
        "handshake_ok_no_appdata_sent: 1" in result.stdout,
        "analyzer must expose idle post-handshake sockets separately from data-path failures",
    )
    require(
        "FakeTLS reliability:" in result.stdout and "ok_rate=" in result.stdout,
        "analyzer must print profile reliability percentages for comparing profiles",
    )
    require(
        "early_drop=1" in result.stdout,
        "analyzer profile reliability summary must expose early post-appdata drops as a first-class counter",
    )
    require(
        "tls_frames=3" in result.stdout,
        "analyzer profile reliability summary must prefer final disconnect FakeTLS record counts over sampled per-frame markers",
    )
    require(
        "Endpoint handshake bursts:" in result.stdout,
        "analyzer must expose per-endpoint handshake bursts",
    )
    require(
        "By connection pattern:" in result.stdout and "strict:" in result.stdout,
        "analyzer must summarize FakeTLS attempts by connection-pattern mode",
    )
    require(
        result.stdout.count("  By connection pattern:") == 1,
        "analyzer must not print the connection-pattern section header twice",
    )
    require(
        "patterns=strict=" in result.stdout,
        "analyzer burst summary must include connection-pattern mix",
    )
    require(
        "admission_queue" in result.stdout,
        "analyzer must preserve the queued-admission marker so GUI 'waiting slot' stalls are visible in logs",
    )
    require(
        "admission_tcp_failure_cooldown" in result.stdout,
        "analyzer must preserve the pre-ClientHello TCP-failure cooldown marker",
    )
    require(
        "admission_freeze_cooldown" in result.stdout
        and "admission_failure_cooldown" in result.stdout,
        "analyzer must preserve non-TCP admission cooldown markers so queued-slot waits can be explained",
    )
    require(
        "client_hello_fragment_plan" in result.stdout
        and "client_hello_fragment" in result.stdout
        and "server_data_before_client_hello_complete" in result.stdout,
        "analyzer must preserve ClientHello fragmentation edge markers for diagnosing fragment-related stalls",
    )
    require(
        "resolved_sslip" in result.stdout
        and "endpoint_failure" in result.stdout
        and "endpoint_handshake_ok" in result.stdout
        and "endpoint_data_path_success" in result.stdout,
        "analyzer must preserve endpoint resilience markers for explaining adaptive recipes and sslip.io fast-path behavior",
    )
    require(
        "admission_hold_after_client_hello_failure" in result.stdout,
        "analyzer must preserve the queued-admission hold marker after post-ClientHello failures",
    )
    require(
        "Java live connection stages:" in result.stdout
        and "client_hello_sent: 1" in result.stdout
        and "server_hello_hmac_ok: 1" in result.stdout,
        "analyzer must summarize Java-side live proxy stage updates",
    )
    require(
        "blocked.example:443 client_hello_sent_no_server_hello: 1" in result.stdout,
        "analyzer must summarize FakeTLS phase verdicts by endpoint",
    )
    require(
        "198.51.100.55:443 dropped_early_after_appdata: 1" in result.stdout,
        "analyzer must include early post-appdata drops in endpoint phase summaries",
    )
    require(
        "198.51.100.77:443 handshake_ok_no_appdata_sent: 1" in result.stdout,
        "analyzer must classify suppressed idle post-handshake closes by endpoint without calling them data-path drops",
    )
    require(
        "198.51.100.88:443 ok: 1" in result.stdout
        and "198.51.100.88:443 dropped_after_appdata" not in result.stdout,
        "suppressed post-appdata close diagnostics must stay out of endpoint drop summaries",
    )
    require(
        "198.51.100.99:443 dropped_after_appdata: 1" in result.stdout,
        "non-suppressed later post-appdata drops must be visible in endpoint phase summaries",
    )
    require(
        "plain.example:443 android_chrome" not in result.stdout,
        "plain dd MTProxy attempts must not be reported in FakeTLS endpoint/profile phases",
    )
    require(
        "Plain MTProxy lifecycle:" in result.stdout,
        "analyzer must summarize non-FakeTLS MTProxy traffic separately from FakeTLS",
    )
    require(
        "Layer recommendations:" in result.stdout,
        "analyzer must print phase-to-layer recommendations so TCP/DNS, ClientHello, dd, and data-path failures are not confused",
    )
    require(
        "dns_endpoint_stability host_resolve_failed=1" in result.stdout
        and "proxy_check_tcp_not_connected=1" in result.stdout
        and "proxy_check_tcp_connected_no_pong=1" in result.stdout
        and "not_ja4_or_drs" in result.stdout,
        "analyzer recommendations must route native and proxy-check DNS/TCP failures to endpoint stability, not JA4/DRS",
    )
    require(
        "faketls_handshake_recipe client_hello_sent_no_server_hello=1" in result.stdout,
        "analyzer recommendations must route pre-ServerHello failures to the phase-adaptive FakeTLS recipe",
    )
    require(
        "plain_dd_endpoint_backoff mtproxy_packet_sent_no_response=1" in result.stdout
        and "dd_no_ja4" in result.stdout,
        "analyzer recommendations must route dd no-response to endpoint backoff/fallback, not FakeTLS JA4",
    )
    require(
        "faketls_data_path post_handshake_no_appdata=0 dropped_early_after_appdata=1 dropped_after_appdata=1 tls_frames_completed=3" in result.stdout,
        "analyzer recommendations must use completed FakeTLS records to identify post-handshake data-path failures including later drops",
    )
    require(
        "plain.example:443 dd account0 dc2 type1: socket_connected=1 connected=1 first_packet_sent=1 first_packet_recv=1 packet_sent_no_response=0 send=1 recv=1 rpc_result=1" in result.stdout,
        "plain MTProxy summary must show successful account/dc/type traffic",
    )
    require(
        "plain.example:443 dd account0 dc2 type2: socket_connected=1 connected=1 first_packet_sent=1 first_packet_recv=0 packet_sent_no_response=1 send=1 recv=0 rpc_result=0 invalid_packet_length=1 auth_404=1 disconnect_2=1" in result.stdout,
        "plain MTProxy summary must expose broken download/media lifecycle separately",
    )
    require(
        "dead.example:443 fail:tcp_not_connected close_reason=2: 1" in result.stdout,
        "proxy-check without socket_connected must be visible as a network/TCP-layer failure",
    )
    require(
        "frozen.example:443 fail:tcp_connected_no_pong close_reason=2: 1" in result.stdout,
        "proxy-check with TCP but without pong must be visible as a post-TCP no-response failure",
    )
    require(
        "ok.example:443 ok:pong: 1" in result.stdout,
        "proxy-check pong success must be visible per endpoint",
    )

    print("MTProxy analyzer guard passed.")


if __name__ == "__main__":
    main()
