#!/usr/bin/env python3
from pathlib import Path
import re
import sys

from mtproxy_phase_contract import (
    analyzer_failure_phases,
    analyzer_phase_names,
    endpoint_key_phases,
    evidence_classes,
    evidence_for_phase,
    java_phase_names,
    java_success_phases,
    java_visible_live_phases,
    native_phase_names,
    phases,
    reconnect_backoff_phases,
    rotation_phases,
)


ROOT = Path(__file__).resolve().parents[1]

DIAGNOSTICS = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckDiagnostics.java"
POLICY = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyPhasePolicy.java"
SCHEDULER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/ProxyCheckScheduler.java"
SOCKET = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
STARTUP_TIMELINE = ROOT / "TMessagesProj/jni/tgnet/MtProxyStartupTimeline.cpp"
CONNECTION = ROOT / "TMessagesProj/jni/tgnet/Connection.cpp"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"
NATIVE_PHASE_CONTRACT = ROOT / "TMessagesProj/jni/tgnet/MtProxyPhaseContract.h"
NATIVE_FAILURE_EVIDENCE_H = ROOT / "TMessagesProj/jni/tgnet/MtProxyFailureEvidence.h"
NATIVE_FAILURE_EVIDENCE_CPP = ROOT / "TMessagesProj/jni/tgnet/MtProxyFailureEvidence.cpp"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def java_constants(diagnostics: str) -> dict[str, str]:
    return dict(re.findall(r'public static final String ([A-Z0-9_]+)\s*=\s*"([a-z0-9_]+)"', diagnostics))


def method_body(source: str, start: str, end: str) -> str:
    start_index = source.find(start)
    if start_index < 0:
        return ""
    end_index = source.find(end, start_index + 1)
    return source[start_index:end_index if end_index >= 0 else len(source)]


def java_cases(source: str, constants: dict[str, str]) -> set[str]:
    return {
        constants[name]
        for name in re.findall(r'case (?:ProxyCheckDiagnostics\.)?([A-Z0-9_]+):', source)
        if name in constants
    }


def native_phase_constants(contract_h: str) -> dict[str, str]:
    return dict(re.findall(r'constexpr const char \*([A-Za-z0-9_]+)\s*=\s*"([a-z0-9_]+)"', contract_h))


def native_constant_values(source: str, constants: dict[str, str]) -> set[str]:
    return {
        constants[name]
        for name in re.findall(r'MtProxyPhase::([A-Za-z0-9_]+)', source)
        if name in constants
    }


def native_diagnostics(socket: str, socket_h: str, startup_timeline: str, connection: str, native_constants: dict[str, str]) -> set[str]:
    native_source = socket + "\n" + startup_timeline
    phases = set(re.findall(r'publishProxyConnectionStage\("([a-z0-9_]+)"\)', native_source))
    phases |= set(re.findall(r'proxyCheckDiagnostic\s*=\s*"([a-z0-9_]+)"', native_source))
    phases |= set(re.findall(r'return "([a-z0-9_]+)"', startup_timeline))
    phases |= set(re.findall(r'closeMtProxyPostClientHelloResponse\("([a-z0-9_]+)"', socket))
    phases |= set(re.findall(r'if \(responseBytes [^}]+return "([a-z0-9_]+)"', socket))
    phases |= set(re.findall(r'proxyCheckDiagnostic\s*=\s*"([a-z0-9_]+)"', socket_h))
    phases |= set(re.findall(r'mtproxy_startup (reconnect_backoff_suppressed)', connection))
    phases |= native_constant_values(socket + "\n" + socket_h + "\n" + startup_timeline + "\n" + connection, native_constants)
    phases.discard("wss_tls_handshake")
    phases -= {
        "none",
        "unknown",
        "admission",
        "host_resolve_admission",
        "endpoint_backoff",
        "probe_wait",
        "dns_coalesce",
        "tcp_connect",
        "pre_tcp_timeout",
    }
    return phases


def string_set_in_block(source: str, start: str, end: str, native_constants: dict[str, str] | None = None) -> set[str]:
    body = method_body(source, start, end)
    values = set(re.findall(r'"([a-z0-9_]+)"', body))
    if native_constants is not None:
        values |= native_constant_values(body, native_constants)
    return values


def analyzer_literal_set(analyzer: str, name: str) -> set[str]:
    match = re.search(rf"{name}\s*=\s*\{{(?P<body>.*?)\}}", analyzer, re.S)
    require(match is not None, f"analyzer must define {name}")
    return set(re.findall(r'"([a-z0-9_]+)"', match.group("body")))


def analyzer_verdict_returns(analyzer: str) -> set[str]:
    body = method_body(analyzer, "    def verdict(self) -> str:", "    def completed_tls_frames")
    return set(re.findall(r'return "([a-z0-9_]+)"', body))


def main() -> int:
    diagnostics = text(DIAGNOSTICS)
    policy = text(POLICY)
    scheduler = text(SCHEDULER)
    socket = text(SOCKET)
    socket_h = text(SOCKET_H)
    startup_timeline = text(STARTUP_TIMELINE)
    connection = text(CONNECTION)
    analyzer = text(ANALYZER)
    native_contract_h = text(NATIVE_PHASE_CONTRACT)
    native_failure_evidence_h = text(NATIVE_FAILURE_EVIDENCE_H)
    native_failure_evidence_cpp = text(NATIVE_FAILURE_EVIDENCE_CPP)

    constants = java_constants(diagnostics)
    native_constants = native_phase_constants(native_contract_h)
    contract_java = java_phase_names()
    legacy_java_aliases = {"unsupported_for_current_client"}
    legacy_analyzer_aliases = {"unsupported_for_current_client"}
    phase_by_name = {phase.name: phase for phase in phases()}
    exhausted_phase = phase_by_name.get("handshake_profiles_exhausted")

    require(
        exhausted_phase is not None
        and exhausted_phase.native
        and exhausted_phase.java
        and exhausted_phase.analyzer,
        "handshake_profiles_exhausted must remain a native/java/analyzer phase",
    )
    require(
        exhausted_phase is not None
        and exhausted_phase.reconnect_backoff
        and exhausted_phase.rotation,
        "handshake_profiles_exhausted must remain reconnect_backoff=True and rotation=True",
    )
    require(
        set(native_constants.values()) == native_phase_names(),
        "MtProxyPhaseContract.h constants must match mtproxy_phase_contract native phases",
    )
    require(
        "enum class MtProxyFailureEvidenceKind" in native_failure_evidence_h
        and "mtProxyEvidenceForPhase" in native_failure_evidence_h
        and "mtProxyFailureEvidenceName" in native_failure_evidence_h,
        "native MTProxy failure evidence contract must expose the enum, phase mapper, and wire-name helper",
    )
    for kind in (
        "None",
        "PreTcpLocalWait",
        "DnsFailure",
        "TcpFailure",
        "NoBytesAfterClientHello",
        "ServerBytesParserFailure",
        "ServerHelloHmacMismatch",
        "PostHandshakeNoAppData",
        "ConfigInvalidSecret",
        "CancelledOrShadowed",
    ):
        require(f"{kind}," in native_failure_evidence_h, f"native failure evidence enum must include {kind}")
    for evidence in evidence_classes():
        require(f'"{evidence}"' in native_failure_evidence_cpp, f"native failure evidence name helper must expose {evidence}")
    require(
        "MtProxyPhase::ServerClosedAfterClientHello" in native_failure_evidence_cpp
        and "responseBytes == 0" in native_failure_evidence_cpp
        and "MtProxyFailureEvidenceKind::ServerBytesParserFailure" in native_failure_evidence_cpp,
        "server_closed_after_client_hello evidence must branch on responseBytes",
    )
    required_evidence_mappings = {
        "connection_not_started": "pre_tcp_local_wait",
        "admission_timeout": "pre_tcp_local_wait",
        "dns_negative_cache_hit": "dns_failure",
        "dns_blocked_zero_address": "dns_failure",
        "host_resolve_failed": "dns_failure",
        "host_resolve_timeout": "dns_failure",
        "tcp_not_connected": "tcp_failure",
        "tcp_connection_refused": "tcp_failure",
        "tcp_connect_timeout": "tcp_failure",
        "faketls_server_hello_wait_timeout": "no_bytes_after_client_hello",
        "tls_alert_after_client_hello": "server_bytes_parser_failure",
        "short_tls_response_after_client_hello": "server_bytes_parser_failure",
        "unrecognized_response_after_client_hello": "server_bytes_parser_failure",
        "server_hello_hmac_mismatch": "server_hello_hmac_mismatch",
        "post_handshake_no_appdata": "post_handshake_no_app_data",
        "secret_parse_invalid_domain_control_char": "config_invalid_secret",
        "secret_parse_invalid_domain": "config_invalid_secret",
    }
    for phase, evidence in required_evidence_mappings.items():
        require(evidence_for_phase(phase) == evidence, f"phase contract must map {phase} to evidence={evidence}")
    require(
        evidence_for_phase("server_closed_after_client_hello", 0) == "no_bytes_after_client_hello"
        and evidence_for_phase("server_closed_after_client_hello", 1) == "server_bytes_parser_failure",
        "phase contract must split server_closed_after_client_hello evidence by response bytes",
    )

    require(set(constants.values()) - legacy_java_aliases == contract_java, "ProxyCheckDiagnostics active constants must match mtproxy_phase_contract")
    require(
        legacy_java_aliases <= set(constants.values()) and "UNSUPPORTED_FOR_CURRENT_CLIENT.equals(diagnostic)" in diagnostics,
        "ProxyCheckDiagnostics must keep documented legacy aliases out of the active phase contract",
    )
    require(
        java_cases(method_body(diagnostics, "public static String normalize", "public static boolean isFailure"), constants) == contract_java,
        "ProxyCheckDiagnostics.normalize must accept exactly the contract Java phases",
    )
    require(
        "kind == Kind.LIVE || kind == Kind.SUCCESS" in policy
        and all(value.upper() in policy for value in java_visible_live_phases()),
        "ProxyPhasePolicy.isLivePhase must match contract live/success phases",
    )
    require(
        all(value.upper() in policy and "usableSuccess" in policy for value in java_success_phases()),
        "ProxyPhasePolicy.isProxyUsableSuccessPhase must match contract success phases",
    )
    require(
        all(value.upper() in policy for value in rotation_phases()) and "public static boolean shouldAccelerateProxyRotation" in policy,
        "ProxyPhasePolicy.shouldAccelerateProxyRotation must match contract rotation phases",
    )
    require(
        all(value.upper() in policy for value in endpoint_key_phases("network")) and "KeyScope.NETWORK" in policy,
        "ProxyPhasePolicy key scope must match contract network-key phases",
    )
    require(
        native_diagnostics(socket, socket_h, startup_timeline, connection, native_constants) == native_phase_names(),
        "native MTProxy diagnostics must match contract native phases",
    )
    require(
        string_set_in_block(connection, "static bool mtProxyDiagnosticNeedsReconnectBackoff", "static uint32_t mtProxyReconnectBackoffBaseMs", native_constants) == reconnect_backoff_phases(),
        "Connection.mtProxyDiagnosticNeedsReconnectBackoff must match contract reconnect phases",
    )
    require(
        analyzer_literal_set(analyzer, "FAKETLS_FAILURE_VERDICTS") - legacy_analyzer_aliases == analyzer_failure_phases(),
        "analyzer FakeTLS failure verdicts must match contract analyzer failure phases",
    )
    require(
        analyzer_literal_set(analyzer, "NON_FAILURE_VERDICTS") <= analyzer_phase_names(),
        "analyzer non-failure verdicts must be declared in the contract",
    )
    require(
        analyzer_verdict_returns(analyzer) <= analyzer_phase_names(),
        "Attempt.verdict returns must be declared in the contract",
    )

    print("MTProxy phase contract guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
