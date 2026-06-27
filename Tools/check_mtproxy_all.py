#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

CHECKS = [
    "check_connection_socket_state_machine_rewrite.py",
    "check_tgnet_network_type_access.py",
    "check_mtproxy_options_contract.py",
    "check_mtproxy_policy_extraction.py",
    "check_mtproxy_faketls_path.py",
    "check_mtproxy_tls_profile_ui.py",
    "check_mtproxy_clienthello_fragmentation.py",
    "check_mtproxy_connection_pattern_modes.py",
    "check_mtproxy_global_handshake_budget.py",
    "check_mtproxy_media_startup_fanout.py",
    "check_mtproxy_startup_cover.py",
    "check_mtproxy_data_layers.py",
    "check_mtproxy_endpoint_resilience_layers.py",
    "check_mtproxy_plain_dd_lifecycle.py",
    "check_mtproxy_phase_contract.py",
    "check_mtproxy_resilience_contract.py",
    "check_mtproxy_rotation_and_soft_mux.py",
    "check_mtproxy_transport_state.py",
    "check_mtproxy_runtime_log_contract.py",
    "check_proxy_connection_live_stages.py",
    "check_proxy_control_plane_policy.py",
    "check_proxy_usable_success_hold.py",
    "check_dns_resolver_fallback.py",
    "check_mtproto_partial_packet_log.py",
    "check_debug_parser_unmapped_logs.py",
    "check_buffer_pool_pressure.py",
    "check_proxy_rotation_engine.py",
    "check_proxy_rotation_behavior.py",
    "check_proxy_check_diagnostics.py",
    "check_proxy_ui_messages.py",
    "check_proxy_check_scheduler.py",
    "check_proxy_check_lifecycle.py",
    "check_mtproxy_analyzer.py",
]


def validate_check_list() -> None:
    expected = {
        path.name
        for path in (ROOT / "Tools").glob("check_mtproxy_*.py")
        if path.name != "check_mtproxy_all.py"
    }
    configured = set(CHECKS)
    missing = sorted(expected - configured)
    stale = sorted(
        check
        for check in configured
        if check.startswith("check_mtproxy_") and not (ROOT / "Tools" / check).exists()
    )
    if missing or stale:
        if missing:
            print("Missing MTProxy checks in check_mtproxy_all.py:", file=sys.stderr)
            for check in missing:
                print(f" - {check}", file=sys.stderr)
        if stale:
            print("Stale MTProxy checks in check_mtproxy_all.py:", file=sys.stderr)
            for check in stale:
                print(f" - {check}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    validate_check_list()
    failed = []
    for check in CHECKS:
        path = ROOT / "Tools" / check
        print(f"==> {check}", flush=True)
        result = subprocess.run([sys.executable, str(path)], cwd=ROOT)
        if result.returncode != 0:
            failed.append((check, result.returncode))
    if failed:
        print("\nMTProxy guard suite failed:", file=sys.stderr)
        for check, code in failed:
            print(f" - {check}: exit {code}", file=sys.stderr)
        return 1
    print("\nMTProxy guard suite passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
