#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile

from analyze_mtproxy_markers import Attempt


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"


def require(condition, message):
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main():
    attempt = Attempt(key="synthetic")
    attempt.add(1, "connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0")
    attempt.add(2, "connection(0x1) mtproxy_startup on_connected tls=0")
    require(
        attempt.verdict() == "connected_without_socket_connected_marker",
        "an attempt that reached on_connected must not be reported as tcp_not_connected",
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        marker_path = Path(handle.name)
        handle.write("logcat.txt:1: connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0\n")
        handle.write("logcat.txt:2: connection(0x1) mtproxy_startup on_connected tls=0\n")
        handle.write(
            "logcat.txt:3: 06-20 15:00:00.000 connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome address=203.0.113.10 port=443\n"
        )
        handle.write("logcat.txt:4: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:5: connection(0x2) mtproxy_startup socket_connected elapsed=90\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write(
            "logcat.txt:7: connection(0x2) mtproxy_startup admission_freeze_detected "
            "key=blocked.example:443:cdn.example elapsed=4500\n"
        )
        handle.write("logcat.txt:8: connection(0x2) mtproxy_startup server_hello_timeout_close elapsed=4500\n")
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.200 connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome address=203.0.113.10 port=443\n"
        )
        handle.write(
            "logcat.txt:9: 06-20 15:00:00.200 connection(0x2) mtproxy_startup admission_grant "
            "key=blocked.example:443:cdn.example priority=20 active=1 max=1\n"
        )
        handle.write("logcat.txt:10: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:11: connection(0x2) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:12: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:13: connection(0x2) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:14: connection(0x2) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:15: connection(0x2) mtproxy_startup first_tls_app_recv payload=105\n")
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
        handle.write("logcat.txt:29: connection(0x3) mtproxy_startup on_connected tls=0\n")
        handle.write("logcat.txt:30: connection(0x3, account0, dc2, type 1) send message invokeWithLayer\n")
        handle.write("logcat.txt:31: connection(0x3, account0, dc2, type 1) received message len 98\n")
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
        handle.write("logcat.txt:37: connection(0x4) mtproxy_startup on_connected tls=0\n")
        handle.write("logcat.txt:38: connection(0x4, account0, dc2, type 2) send message getFile\n")
        handle.write("logcat.txt:39: connection(0x4, account0, dc2, type 2) reset auth key due to -404 error\n")
        handle.write("logcat.txt:40: connection(0x4, account0, dc2, type 2) received invalid packet length\n")
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
            require(attempts_csv.exists(), "analyzer must write per-attempt CSV when --out-dir is passed")
            require(endpoint_csv.exists(), "analyzer must write endpoint/profile stats CSV when --out-dir is passed")
            require(
                "blocked.example:443" in endpoint_csv.read_text(encoding="utf-8"),
                "endpoint/profile CSV must include FakeTLS endpoint names",
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
        "FakeTLS reliability:" in result.stdout and "ok_rate=" in result.stdout,
        "analyzer must print profile reliability percentages for comparing profiles",
    )
    require(
        "Endpoint handshake bursts:" in result.stdout,
        "analyzer must expose per-endpoint handshake bursts",
    )
    require(
        "blocked.example:443 client_hello_sent_no_server_hello: 1" in result.stdout,
        "analyzer must summarize FakeTLS phase verdicts by endpoint",
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
        "plain.example:443 dd account0 dc2 type1: connected=1 send=1 recv=1 rpc_result=1" in result.stdout,
        "plain MTProxy summary must show successful account/dc/type traffic",
    )
    require(
        "plain.example:443 dd account0 dc2 type2: connected=1 send=1 recv=0 rpc_result=0 invalid_packet_length=1 auth_404=1 disconnect_2=1" in result.stdout,
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
