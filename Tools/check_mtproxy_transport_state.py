#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
HEADER = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
MACHINE = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocketStateMachine.cpp"
MACHINE_HEADER = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocketStateMachine.h"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str, next_signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    end = text.find(next_signature, start + len(signature))
    return text[start:] if end == -1 else text[start:end]


def main() -> int:
    failures: list[str] = []
    socket = read(SOCKET)
    header = read(HEADER)
    machine = read(MACHINE)
    machine_header = read(MACHINE_HEADER)
    state_source = socket + "\n" + machine
    header_source = header + "\n" + machine_header
    analyzer = read(ANALYZER)

    for state in (
        "idle",
        "prepared",
        "waiting_gate",
        "tcp_connecting",
        "epoll_registered",
        "faketls_handshake",
        "mtproto_ready",
        "closing",
    ):
        require(state in state_source or state in header_source, f"transport state '{state}' must be named in native code", failures)

    require("enum class LifecycleState" in machine_header, "ConnectionSocketStateMachine must expose the lifecycle enum", failures)
    require("LifecycleState lifecycle" in machine_header, "ConnectionSocketStateMachine must keep one explicit lifecycle state", failures)
    require("bool registered" in machine_header, "ConnectionSocketStateMachine must track successful epoll registration explicitly", failures)
    require("bool adjustWriteAfterPreTcpGate" in machine_header, "ConnectionSocketStateMachine must track writes queued before live epoll", failures)
    require("bool tcpConnectAttemptStarted" in machine_header, "ConnectionSocketStateMachine must track whether a real TCP connect was attempted", failures)
    require("bool dnsResolveAttemptStarted" in machine_header, "ConnectionSocketStateMachine must track whether delegate DNS was actually started", failures)
    require("std::string preTcpWaitPhase" in machine_header, "ConnectionSocketStateMachine must track the active local pre-TCP wait phase", failures)
    require("int64_t preTcpWaitDeadlineMs" in machine_header, "ConnectionSocketStateMachine must track the active local pre-TCP wait deadline", failures)
    require('std::string proxyCheckDiagnostic = "connection_not_started"' in machine_header, "ConnectionSocketStateMachine diagnostic default must not be tcp_not_connected before socket_connect_start", failures)
    private_start = header.find("private:")
    protected_start = header.find("protected:")
    enum_pos = machine_header.find("enum class LifecycleState")
    state_field_pos = machine_header.find("LifecycleState lifecycle")
    require(
        private_start >= 0
        and protected_start >= 0
        and enum_pos >= 0
        and state_field_pos >= 0,
        "lifecycle enum and current state storage must be machine-owned implementation details",
        failures,
    )
    for helper in (
        "transportStateName",
        "isAllowedTransportTransition",
        "setTransportState",
        "proxyAuthStateName",
        "isAllowedProxyAuthTransition",
        "setProxyAuthState",
        "tlsStateName",
        "isAllowedTlsStateTransition",
        "setTlsState",
        "logTransportSnapshot",
        "logTransportInvariant",
        "findTransportActionRule",
        "isTransportStateAllowedForAction",
        "checkTransportActionRequirements",
        "setSocketFd",
        "setEpollRegistered",
        "canCreateSocket",
        "canUseLiveEpollSocket",
        "canModifyEpollWriteInterest",
        "canSendPendingClientHello",
        "canSendPendingTlsFrame",
        "canSendSocksHandshakeFrame",
        "canSendPlainMtProtoPayload",
        "canStartTcpConnect",
        "canRegisterEpollSocket",
        "canConfigureOpenSocket",
        "canCheckSocketError",
        "canProcessEpollEvent",
        "checkCloseSocketAction",
        "canUnregisterEpollSocket",
        "canCloseNativeSocket",
        "setProxyHandshakeAdmissionState",
        "checkProxyHandshakeAdmissionRelease",
        "setProxyEndpointTcpConnectGateState",
        "setProxyEndpointBackoffReady",
        "setProxyEndpointDnsCoalesceReady",
        "setAdjustWriteOpAfterResolve",
        "setAdjustWriteOpAfterPreTcpGate",
        "setMtProxyTcpConnectAttemptStarted",
        "setMtProxyDnsResolveAttemptStarted",
        "setMtProxyPreTcpWaitPhase",
        "classifyMtProxyPreTcpTimeoutDiagnostic",
        "deriveMtProxyTerminalDiagnostic",
        "mtProxyDiagnosticIsLocalSchedulerTimeout",
        "queueAdjustWriteOpAfterOutboundAppend",
        "setMtProxySocketConnectedLogged",
        "canStartHostResolve",
        "checkHostResolveCallback",
        "setWaitingForHostResolve",
        "canNotifyConnected",
        "setSocketCloseNotified",
        "setConnectedNotified",
        "canDeliverReceivedData",
        "canSendWssFrame",
        "canQueueOutboundBuffer",
        "canSendRawSocketBytes",
        "canReceiveRawSocketBytes",
    ):
        require(helper in header_source and helper in state_source, f"ConnectionSocket state-machine rewrite must implement {helper}", failures)

    for field in (
        "transport_state=%s",
        "epoll_registered=%d",
        "admission_active=%d",
        "admission_queued=%d",
        "tcp_gate_active=%d",
        "waiting_resolve=%d",
        "proxy_state=%d",
        "tls_state=%d",
    ):
        require(field in state_source, f"native transport logs must include stable field {field}", failures)

    require(
        "void ConnectionSocket::recordMtProxyEndpointHandshakeOk" in socket
        and "void ConnectionSocket::recordMtProxyEndpointDataPathSuccess" in socket
        and "recordMtProxyEndpointSuccess" not in header,
        "endpoint success must be split into handshake-ok and data-path-success helpers",
        failures,
    )

    server_hello_body = socket[
        socket.find('publishProxyConnectionStage("server_hello_hmac_ok")'):
        socket.find('proxyCheckDiagnostic = "post_handshake_no_appdata"', socket.find('publishProxyConnectionStage("server_hello_hmac_ok")'))
    ]
    require(
        'recordMtProxyEndpointHandshakeOk("server_hello_hmac_ok")' in server_hello_body
        and "recordMtProxyEndpointDataPathSuccess" not in server_hello_body,
        "server_hello_hmac_ok must record handshake-ok only, not data-path success",
        failures,
    )

    tls_app_body = socket[
        socket.find('publishProxyConnectionStage("first_tls_app_recv")'):
        socket.find('onReceivedData(tlsBuffer)', socket.find('publishProxyConnectionStage("first_tls_app_recv")'))
    ]
    require(
        'recordMtProxyEndpointDataPathSuccess("first_tls_app_recv")' in tls_app_body,
        "first_tls_app_recv must record data-path success",
        failures,
    )
    require(
        'canDeliverReceivedData("first_tls_app_recv")' in tls_app_body,
        "first_tls_app_recv must use the transport action policy before onReceivedData",
        failures,
    )

    plain_success_body = socket[
        socket.find('publishProxyConnectionStage("first_mtproxy_packet_recv")'):
        socket.find("void ConnectionSocket::rotateMtProxyTlsProfileOnFailureIfNeeded", socket.find('publishProxyConnectionStage("first_mtproxy_packet_recv")'))
    ]
    first_plain_recv_log = 'DEBUG_D("connection(%p) mtproxy_startup first_mtproxy_packet_recv bytes=%u secret_kind=%s"'
    first_plain_recv_success = 'recordMtProxyEndpointDataPathSuccess("first_mtproxy_packet_recv")'
    require(
        first_plain_recv_success in plain_success_body,
        "first_mtproxy_packet_recv must record data-path success",
        failures,
    )
    require(
        first_plain_recv_log in plain_success_body
        and plain_success_body.find(first_plain_recv_log) < plain_success_body.find(first_plain_recv_success),
        "first_mtproxy_packet_recv must log app-data evidence before endpoint data-path success",
        failures,
    )
    plain_delivery_body = socket[
        socket.find("markMtProxyFirstPlainDataReceived((uint32_t) readCount);"):
        socket.find("onReceivedData(buffer);", socket.find("markMtProxyFirstPlainDataReceived((uint32_t) readCount);"))
    ]
    require(
        'canDeliverReceivedData("first_mtproxy_packet_recv")' in plain_delivery_body,
        "first_mtproxy_packet_recv must use the transport action policy before onReceivedData",
        failures,
    )

    adjust_body = method_body(socket, "void ConnectionSocket::adjustWriteOp()", "void ConnectionSocket::setTimeout")
    require(
        'canModifyEpollWriteInterest("adjustWriteOp")' in adjust_body
        and "stateMachine.epollCtlMod" in adjust_body,
        "adjustWriteOp must use the transport action policy before epoll_ctl MOD",
        failures,
    )

    client_hello_body = method_body(socket, "bool ConnectionSocket::sendPendingClientHello()", "void ConnectionSocket::clearPendingTlsFrame")
    require(
        "if (!canSendPendingClientHello())" in client_hello_body,
        "sendPendingClientHello must use the transport action policy",
        failures,
    )

    tls_frame_body = method_body(socket, "bool ConnectionSocket::sendPendingTlsFrame()", "uint32_t ConnectionSocket::nextMtProxyTlsRecordPayloadSize")
    require(
        "if (!canSendPendingTlsFrame())" in tls_frame_body,
        "sendPendingTlsFrame must use the transport action policy",
        failures,
    )
    client_hello_fragment_body = method_body(socket, "bool ConnectionSocket::sendPendingClientHelloFragment", "bool ConnectionSocket::sendPendingClientHello()")
    require(
        'canSendRawSocketBytes("raw_client_hello_send")' in client_hello_fragment_body
        and "stateMachine.sendBytes" in client_hello_fragment_body,
        "ClientHello raw send must use the raw socket transport action policy",
        failures,
    )
    require(
        'canSendRawSocketBytes("raw_tls_frame_send")' in tls_frame_body
        and "stateMachine.sendBytes" in tls_frame_body,
        "TLS frame raw send must use the raw socket transport action policy",
        failures,
    )

    modify_policy_body = method_body(socket, "bool ConnectionSocket::canModifyEpollWriteInterest", "bool ConnectionSocket::canSendPendingClientHello")
    require(
        "checkTransportActionRequirements(action)" in modify_policy_body,
        "canModifyEpollWriteInterest must use the shared action requirements policy",
        failures,
    )
    hello_policy_body = method_body(socket, "bool ConnectionSocket::canSendPendingClientHello", "bool ConnectionSocket::canSendPendingTlsFrame")
    require(
        'checkTransportActionRequirements("sendPendingClientHello")' in hello_policy_body,
        "canSendPendingClientHello must delegate FakeTLS/proxy/fd/epoll checks to the action policy",
        failures,
    )
    tls_policy_body = method_body(socket, "bool ConnectionSocket::canSendPendingTlsFrame", "bool ConnectionSocket::canSendSocksHandshakeFrame")
    require(
        'checkTransportActionRequirements("sendPendingTlsFrame")' in tls_policy_body,
        "canSendPendingTlsFrame must delegate mtproto_ready/fd/epoll checks to the action policy",
        failures,
    )
    epoll_registered_body = method_body(socket, "void ConnectionSocket::setEpollRegistered", "bool ConnectionSocket::canCreateSocket")
    require(
        "stateMachine.setEpollRegistered(registered)" in epoll_registered_body
        and "epoll_registration_state_change" in epoll_registered_body
        and "epoll_registered=%d" in epoll_registered_body
        and "transport_state=%s" in epoll_registered_body,
        "epollRegistered writes must be centralized and logged through setEpollRegistered",
        failures,
    )
    direct_epoll_registered_writes = [
        line.strip()
        for line in socket.splitlines()
        if "epollRegistered =" in line and "==" not in line
    ]
    require(
        direct_epoll_registered_writes == [],
        "epollRegistered must be written only by setEpollRegistered",
        failures,
    )
    socket_fd_body = method_body(socket, "void ConnectionSocket::setSocketFd", "void ConnectionSocket::setEpollRegistered")
    require(
        "stateMachine.setSocketFd(fd)" in socket_fd_body
        and "socket_fd_state_change" in socket_fd_body
        and "open=%d" in socket_fd_body
        and "transport_state=%s" in socket_fd_body
        and "epoll_registered=%d" in socket_fd_body
        and "admission_active=%d" in socket_fd_body
        and "admission_queued=%d" in socket_fd_body
        and "tcp_gate_active=%d" in socket_fd_body
        and "waiting_resolve=%d" in socket_fd_body
        and "proxy_state=%d" in socket_fd_body
        and "tls_state=%d" in socket_fd_body,
        "socketFd writes must be centralized and logged through setSocketFd",
        failures,
    )
    direct_socket_fd_writes = [
        line.strip()
        for line in socket.splitlines()
        if "socketFd =" in line and "==" not in line and "!=" not in line and ">=" not in line and "<=" not in line
    ]
    require(
        direct_socket_fd_writes == [],
        "socketFd must be written only by setSocketFd",
        failures,
    )
    create_socket_policy_body = method_body(socket, "bool ConnectionSocket::canCreateSocket", "bool ConnectionSocket::canUseLiveEpollSocket")
    require(
        "checkTransportActionRequirements(action)" in create_socket_policy_body,
        "canCreateSocket must delegate prepared/no-fd/no-epoll checks to the shared action policy",
        failures,
    )
    live_socket_body = method_body(socket, "bool ConnectionSocket::canUseLiveEpollSocket", "bool ConnectionSocket::canModifyEpollWriteInterest")
    require(
        "socketFd < 0" in live_socket_body
        and "!epollRegistered" in live_socket_body
        and "logTransportInvariant(action" in live_socket_body,
        "canUseLiveEpollSocket must guard fd/epoll liveness and log invariants",
        failures,
    )
    socks_policy_body = method_body(socket, "bool ConnectionSocket::canSendSocksHandshakeFrame", "bool ConnectionSocket::canSendPlainMtProtoPayload")
    require(
        "checkTransportActionRequirements(action)" in socks_policy_body
        and "expectedProxyAuthState" in socks_policy_body,
        "canSendSocksHandshakeFrame must delegate epoll/proxy/fd checks to the action policy",
        failures,
    )
    plain_policy_body = method_body(socket, "bool ConnectionSocket::canSendPlainMtProtoPayload", "void ConnectionSocket::clearPendingClientHello")
    require(
        'checkTransportActionRequirements("sendPlainMtProtoPayload")' in plain_policy_body,
        "canSendPlainMtProtoPayload must delegate mtproto_ready/proxy/tls/fd/epoll checks to the action policy",
        failures,
    )

    on_event_body = method_body(socket, "void ConnectionSocket::onEvent", "void ConnectionSocket::adjustWriteOp")
    require(
        "if (!canProcessEpollEvent())" in on_event_body,
        "onEvent must use the transport action policy before processing epoll events",
        failures,
    )
    require(
        "if (!canReceiveRawSocketBytes())" in on_event_body
        and "stateMachine.recvBytes" in on_event_body,
        "raw socket recv must use the raw socket transport action policy",
        failures,
    )
    for action, expected_state in (
        ("socks_method_select", "1"),
        ("socks_auth", "3"),
        ("socks_connect", "5"),
    ):
        require(
            f'canSendSocksHandshakeFrame("{action}", {expected_state})' in on_event_body,
            f"{action} send must use the transport action policy",
            failures,
        )
    for action in (
        "raw_socks_method_send",
        "raw_socks_auth_send",
        "raw_socks_connect_send",
        "raw_plain_mtproto_send",
    ):
        require(
            f'canSendRawSocketBytes("{action}")' in on_event_body,
            f"{action} must use the raw socket transport action policy",
            failures,
        )
    require(
        "if (!canSendPlainMtProtoPayload())" in on_event_body,
        "plain MTProto payload send must use the transport action policy",
        failures,
    )

    open_connection_body = method_body(socket, "void ConnectionSocket::openConnection(std::string address", "void ConnectionSocket::openConnectionInternal")
    for action in (
        "create_wss_socket",
        "create_wss_ipv6_socket",
        "create_proxy_socket",
        "create_direct_socket",
    ):
        require(
            f'canCreateSocket("{action}")' in open_connection_body,
            f"{action} must use the socket-creation transport action policy",
            failures,
        )
    require(
        "NoSocket" in header_source
        and "TransportSocketPolicy::NoSocket" in state_source
        and "socket.fd >= 0" in machine
        and "epoll.registered" in machine,
        "socket creation policy must explicitly require prepared state with no open socket and no epoll registration",
        failures,
    )

    open_internal_body = method_body(socket, "void ConnectionSocket::openConnectionInternal", "int32_t ConnectionSocket::checkSocketError")
    circuit_pos = open_internal_body.find("scheduleMtProxyEndpointCircuitBreakerIfNeeded(ipv6)")
    admission_pos = open_internal_body.find("scheduleProxyHandshakeAdmissionIfNeeded(ipv6, MT_PROXY_HANDSHAKE_TIMER_ADMISSION)")
    configure_pos = open_internal_body.find("if (!canConfigureOpenSocket())")
    tcp_gate_pos = open_internal_body.find("scheduleMtProxyEndpointTcpConnectGateIfNeeded(ipv6)")
    connect_start_pos = open_internal_body.find('publishProxyConnectionStage("socket_connect_start")')
    require(
        -1 not in (circuit_pos, admission_pos, configure_pos, tcp_gate_pos, connect_start_pos)
        and circuit_pos < admission_pos < configure_pos < tcp_gate_pos < connect_start_pos,
        "openConnectionInternal must run endpoint circuit breaker, admission, socket configure, then TCP gate immediately before socket_connect_start",
        failures,
    )
    require(
        "if (!canConfigureOpenSocket())" in open_internal_body
        and "setsockopt(socketFd" in open_internal_body
        and "fcntl(socketFd" in open_internal_body,
        "socket option/nonblocking setup must use the transport action policy before configuration side effects",
        failures,
    )
    require(
        "if (!canStartTcpConnect())" in open_internal_body
        and "stateMachine.connectNativeSocket" in open_internal_body,
        "connect must use the transport action policy",
        failures,
    )
    require(
        "if (!canRegisterEpollSocket())" in open_internal_body
        and "stateMachine.epollCtlAdd" in open_internal_body,
        "EPOLL_CTL_ADD must use the transport action policy",
        failures,
    )
    start_connect_body = method_body(socket, "bool ConnectionSocket::canStartTcpConnect", "bool ConnectionSocket::canRegisterEpollSocket")
    require(
        'checkTransportActionRequirements("connect")' in start_connect_body,
        "canStartTcpConnect must delegate tcp_connecting/fd/no-epoll checks to the action policy",
        failures,
    )
    register_epoll_body = method_body(socket, "bool ConnectionSocket::canRegisterEpollSocket", "bool ConnectionSocket::isCurrentTransportWss")
    require(
        'checkTransportActionRequirements("epoll_ctl_add")' in register_epoll_body,
        "canRegisterEpollSocket must delegate tcp_connecting/fd/no-epoll checks to the action policy",
        failures,
    )
    configure_socket_policy_body = method_body(socket, "bool ConnectionSocket::canConfigureOpenSocket", "bool ConnectionSocket::canCheckSocketError")
    require(
        'checkTransportActionRequirements("configure_socket")' in configure_socket_policy_body,
        "canConfigureOpenSocket must delegate prepared/fd/no-epoll checks to the shared action requirements policy",
        failures,
    )
    check_socket_error_body = method_body(socket, "int32_t ConnectionSocket::checkSocketError", "bool ConnectionSocket::isCurrentTransportWss")
    require(
        "if (!canCheckSocketError())" in check_socket_error_body
        and "getsockopt(socketFd" in check_socket_error_body,
        "checkSocketError must use the transport action policy before getsockopt",
        failures,
    )
    check_socket_error_policy_body = method_body(socket, "bool ConnectionSocket::canCheckSocketError", "bool ConnectionSocket::canProcessEpollEvent")
    require(
        'checkTransportActionRequirements("checkSocketError")' in check_socket_error_policy_body,
        "canCheckSocketError must delegate live-fd/epoll checks to the shared action requirements policy",
        failures,
    )
    admission_release_body = method_body(socket, "void ConnectionSocket::releaseProxyHandshakeAdmission", "bool ConnectionSocket::scheduleMtProxyEndpointCircuitBreakerIfNeeded")
    require(
        'checkProxyHandshakeAdmissionRelease(succeeded, reason)' in admission_release_body,
        "releaseProxyHandshakeAdmission must run the transport-state admission release check",
        failures,
    )
    require(
        'strcmp(reason, "tcp_connect_gate_wait") == 0' in admission_release_body
        and "isNeutralSchedulerWaitRelease" in admission_release_body
        and "shouldApplyTcpFailureCooldown = wasActive && !isNeutralSchedulerWaitRelease && tcpConnectAttemptStarted" in admission_release_body
        and "else if (!succeeded && wasActive && !isNeutralSchedulerWaitRelease && mtProxyConnectionPatternUsesCooldown(connectionPatternMode))" in admission_release_body,
        "releaseProxyHandshakeAdmission must treat tcp_connect_gate_wait as a neutral scheduler release with no failure cooldown",
        failures,
    )
    admission_release_policy_body = method_body(socket, "void ConnectionSocket::checkProxyHandshakeAdmissionRelease", "void ConnectionSocket::clearPendingClientHello")
    require(
        'checkTransportActionRequirements("releaseProxyHandshakeAdmission")' in admission_release_policy_body
        and 'logTransportInvariant("releaseProxyHandshakeAdmission"' in admission_release_policy_body,
        "checkProxyHandshakeAdmissionRelease must allow expected lifecycle states and log invariant releases",
        failures,
    )
    tcp_gate_state_body = method_body(socket, "void ConnectionSocket::setProxyEndpointTcpConnectGateState", "bool ConnectionSocket::canStartHostResolve")
    require(
        "proxyEndpointTcpConnectActive = nextActive;" in tcp_gate_state_body
        and "proxyEndpointTcpConnectReady = nextReady;" in tcp_gate_state_body
        and "proxyEndpointTcpConnectGatePublished = nextPublished;" in tcp_gate_state_body
        and "tcp_connect_gate_state_change" in tcp_gate_state_body
        and "tcp_gate_active=%d" in tcp_gate_state_body
        and "transport_state=%s" in tcp_gate_state_body
        and "epoll_registered=%d" in tcp_gate_state_body,
        "TCP connect gate flags must be centralized and logged through setProxyEndpointTcpConnectGateState",
        failures,
    )
    direct_tcp_gate_writes = [
        line.strip()
        for line in socket.splitlines()
        if (
            "proxyEndpointTcpConnectActive =" in line
            or "proxyEndpointTcpConnectReady =" in line
            or "proxyEndpointTcpConnectGatePublished =" in line
        )
        and "==" not in line
    ]
    require(
        direct_tcp_gate_writes == [
            "proxyEndpointTcpConnectActive = nextActive;",
            "proxyEndpointTcpConnectReady = nextReady;",
            "proxyEndpointTcpConnectGatePublished = nextPublished;",
        ],
        "TCP connect gate flags must be written only by setProxyEndpointTcpConnectGateState",
        failures,
    )
    tcp_gate_schedule_body = method_body(socket, "bool ConnectionSocket::scheduleMtProxyEndpointTcpConnectGateIfNeeded", "void ConnectionSocket::releaseMtProxyEndpointTcpConnect")
    neutral_release_pos = tcp_gate_schedule_body.find('releaseProxyHandshakeAdmission(false, "tcp_connect_gate_wait")')
    tcp_gate_timer_pos = tcp_gate_schedule_body.find("scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE, ipv6)")
    require(
        neutral_release_pos >= 0
        and tcp_gate_timer_pos >= 0
        and neutral_release_pos < tcp_gate_timer_pos,
        "TCP gate waits after admission must release the admission slot neutrally before scheduling the gate timer",
        failures,
    )
    endpoint_backoff_ready_body = method_body(socket, "void ConnectionSocket::setProxyEndpointBackoffReady", "void ConnectionSocket::setProxyEndpointDnsCoalesceReady")
    require(
        "proxyEndpointBackoffReady = ready;" in endpoint_backoff_ready_body
        and "endpoint_backoff_ready_state_change" in endpoint_backoff_ready_body
        and "transport_state=%s" in endpoint_backoff_ready_body
        and "epoll_registered=%d" in endpoint_backoff_ready_body,
        "endpoint backoff ready must be centralized and logged through setProxyEndpointBackoffReady",
        failures,
    )
    endpoint_dns_ready_body = method_body(socket, "void ConnectionSocket::setProxyEndpointDnsCoalesceReady", "void ConnectionSocket::setAdjustWriteOpAfterResolve")
    require(
        "proxyEndpointDnsCoalesceReady = ready;" in endpoint_dns_ready_body
        and "dns_coalesce_ready_state_change" in endpoint_dns_ready_body
        and "transport_state=%s" in endpoint_dns_ready_body
        and "epoll_registered=%d" in endpoint_dns_ready_body,
        "DNS coalesce ready must be centralized and logged through setProxyEndpointDnsCoalesceReady",
        failures,
    )
    write_after_resolve_body = method_body(socket, "void ConnectionSocket::setAdjustWriteOpAfterResolve", "void ConnectionSocket::setAdjustWriteOpAfterPreTcpGate")
    require(
        "adjustWriteOpAfterResolve = pending;" in write_after_resolve_body
        and "write_after_resolve_state_change" in write_after_resolve_body
        and "transport_state=%s" in write_after_resolve_body
        and "epoll_registered=%d" in write_after_resolve_body,
        "deferred write-after-resolve latch must be centralized and logged through setAdjustWriteOpAfterResolve",
        failures,
    )
    write_after_pre_tcp_body = method_body(socket, "void ConnectionSocket::setAdjustWriteOpAfterPreTcpGate", "void ConnectionSocket::setMtProxyTcpConnectAttemptStarted")
    require(
        "adjustWriteOpAfterPreTcpGate = pending;" in write_after_pre_tcp_body
        and "write_after_pre_tcp_gate_state_change" in write_after_pre_tcp_body
        and "transport_state=%s" in write_after_pre_tcp_body
        and "epoll_registered=%d" in write_after_pre_tcp_body,
        "deferred write-after-pre-TCP latch must be centralized and logged through setAdjustWriteOpAfterPreTcpGate",
        failures,
    )
    tcp_started_body = method_body(socket, "void ConnectionSocket::setMtProxyTcpConnectAttemptStarted", "void ConnectionSocket::setMtProxySocketConnectedLogged")
    require(
        "tcpConnectAttemptStarted = started;" in tcp_started_body
        and "tcp_connect_attempt_started_state_change" in tcp_started_body
        and "transport_state=%s" in tcp_started_body
        and "epoll_registered=%d" in tcp_started_body,
        "TCP connect-attempt latch must be centralized and logged through setMtProxyTcpConnectAttemptStarted",
        failures,
    )
    dns_started_body = method_body(socket, "void ConnectionSocket::setMtProxyDnsResolveAttemptStarted", "void ConnectionSocket::setMtProxyPreTcpWaitPhase")
    require(
        "dnsResolveAttemptStarted = started;" in dns_started_body
        and "dns_resolve_attempt_started_state_change" in dns_started_body
        and "transport_state=%s" in dns_started_body
        and "waiting_resolve=%d" in dns_started_body,
        "DNS resolve-attempt latch must be centralized and logged through setMtProxyDnsResolveAttemptStarted",
        failures,
    )
    pre_tcp_wait_body = method_body(socket, "void ConnectionSocket::setMtProxyPreTcpWaitPhase", "void ConnectionSocket::classifyMtProxyPreTcpTimeoutDiagnostic")
    require(
        "preTcpWaitPhase = phase" in pre_tcp_wait_body
        and "preTcpWaitDeadlineMs = deadlineMs;" in pre_tcp_wait_body
        and "pre_tcp_wait_state_change" in pre_tcp_wait_body
        and "transport_state=%s" in pre_tcp_wait_body,
        "pre-TCP wait phase/deadline must be centralized and logged through setMtProxyPreTcpWaitPhase",
        failures,
    )
    classify_pre_tcp_body = method_body(socket, "void ConnectionSocket::classifyMtProxyPreTcpTimeoutDiagnostic", "std::string ConnectionSocket::deriveMtProxyTerminalDiagnostic")
    require(
        '"tcp_connect_gate_timeout"' in classify_pre_tcp_body
        and '"admission_timeout"' in classify_pre_tcp_body
        and '"endpoint_cooldown_timeout"' in classify_pre_tcp_body
        and '"dns_coalesce_timeout"' in classify_pre_tcp_body
        and '"host_resolve_timeout"' in classify_pre_tcp_body
        and '"host_resolve_failed"' not in classify_pre_tcp_body
        and "preTcpWaitPhase" in classify_pre_tcp_body
        and "dnsResolveAttemptStarted" in classify_pre_tcp_body
        and "tcpConnectAttemptStarted" in classify_pre_tcp_body,
        "pre-TCP timeout classifier must derive local/DNS timeout phases from milestones, not from pending host alone",
        failures,
    )
    terminal_body = method_body(socket, "std::string ConnectionSocket::deriveMtProxyTerminalDiagnostic", "void ConnectionSocket::setMtProxySocketConnectedLogged")
    require(
        "classifyMtProxyPreTcpTimeoutDiagnostic" in terminal_body
        and '"tcp_not_connected"' in terminal_body
        and "tcpConnectAttemptStarted" in terminal_body
        and "mtproxySocketConnectedLogged" in terminal_body
        and "dnsResolveAttemptStarted" in terminal_body,
        "closeSocket must derive terminal diagnostics from real DNS/TCP milestones before publishing",
        failures,
    )
    local_phase_body = method_body(socket, "bool ConnectionSocket::mtProxyDiagnosticIsLocalSchedulerTimeout", "void ConnectionSocket::setMtProxySocketConnectedLogged")
    require(
        '"connection_not_started"' in local_phase_body
        and '"admission_timeout"' in local_phase_body
        and '"tcp_connect_gate_timeout"' in local_phase_body
        and '"endpoint_cooldown_timeout"' in local_phase_body
        and '"dns_coalesce_timeout"' in local_phase_body
        and '"tcp_not_connected"' not in local_phase_body,
        "native local scheduler timeout helper must exclude real TCP failures",
        failures,
    )
    queue_write_body = method_body(socket, "void ConnectionSocket::queueAdjustWriteOpAfterOutboundAppend", "void ConnectionSocket::adjustWriteOp")
    require(
        "setAdjustWriteOpAfterPreTcpGate(true" in queue_write_body
        and "setAdjustWriteOpAfterResolve(true" in queue_write_body
        and "adjustWriteOp();" in queue_write_body,
        "outbound appends must use a shared deferred-write helper before touching epoll",
        failures,
    )
    write_raw_body = method_body(socket, "void ConnectionSocket::writeBuffer(uint8_t", "void ConnectionSocket::writeBuffer(NativeByteBuffer")
    write_buffer_body = method_body(socket, "void ConnectionSocket::writeBuffer(NativeByteBuffer", "void ConnectionSocket::queueAdjustWriteOpAfterOutboundAppend")
    require(
        'queueAdjustWriteOpAfterOutboundAppend("writeBufferRaw")' in write_raw_body
        and "adjustWriteOp();" not in write_raw_body,
        "writeBuffer(uint8_t*) must defer pre-epoll write interest instead of calling adjustWriteOp directly",
        failures,
    )
    require(
        'queueAdjustWriteOpAfterOutboundAppend("writeBuffer")' in write_buffer_body
        and "adjustWriteOp();" not in write_buffer_body,
        "writeBuffer(NativeByteBuffer*) must defer pre-epoll write interest instead of calling adjustWriteOp directly",
        failures,
    )
    direct_write_after_pre_tcp_writes = [
        line.strip()
        for line in socket.splitlines()
        if "adjustWriteOpAfterPreTcpGate =" in line and "==" not in line
    ]
    require(
        direct_write_after_pre_tcp_writes == ["adjustWriteOpAfterPreTcpGate = pending;"],
        "pre-TCP deferred write latch must be written only by setAdjustWriteOpAfterPreTcpGate",
        failures,
    )
    direct_tcp_started_writes = [
        line.strip()
        for line in socket.splitlines()
        if "tcpConnectAttemptStarted =" in line and "==" not in line
    ]
    direct_dns_started_writes = [
        line.strip()
        for line in socket.splitlines()
        if "dnsResolveAttemptStarted =" in line and "==" not in line
    ]
    direct_pre_tcp_phase_writes = [
        line.strip()
        for line in socket.splitlines()
        if line.strip().startswith("preTcpWaitPhase =")
    ]
    direct_pre_tcp_deadline_writes = [
        line.strip()
        for line in socket.splitlines()
        if line.strip().startswith("preTcpWaitDeadlineMs =")
    ]
    require(
        direct_tcp_started_writes == ["tcpConnectAttemptStarted = started;"],
        "TCP connect-attempt latch must be written only by setMtProxyTcpConnectAttemptStarted",
        failures,
    )
    require(
        direct_dns_started_writes == ["dnsResolveAttemptStarted = started;"],
        "DNS resolve-attempt latch must be written only by setMtProxyDnsResolveAttemptStarted",
        failures,
    )
    require(
        direct_pre_tcp_phase_writes == ["preTcpWaitPhase = phase == nullptr ? \"\" : phase;"],
        "pre-TCP wait phase must be written only by setMtProxyPreTcpWaitPhase",
        failures,
    )
    require(
        direct_pre_tcp_deadline_writes == ["preTcpWaitDeadlineMs = deadlineMs;"],
        "pre-TCP wait deadline must be written only by setMtProxyPreTcpWaitPhase",
        failures,
    )
    socket_connected_logged_body = method_body(socket, "void ConnectionSocket::setMtProxySocketConnectedLogged", "bool ConnectionSocket::canStartHostResolve")
    require(
        "mtproxySocketConnectedLogged = logged;" in socket_connected_logged_body
        and "socket_connected_logged_state_change" in socket_connected_logged_body
        and "transport_state=%s" in socket_connected_logged_body
        and "epoll_registered=%d" in socket_connected_logged_body,
        "socket-connected logged latch must be centralized and logged through setMtProxySocketConnectedLogged",
        failures,
    )
    direct_endpoint_backoff_writes = [
        line.strip()
        for line in socket.splitlines()
        if "proxyEndpointBackoffReady =" in line and "==" not in line
    ]
    direct_endpoint_dns_writes = [
        line.strip()
        for line in socket.splitlines()
        if "proxyEndpointDnsCoalesceReady =" in line and "==" not in line
    ]
    direct_write_after_resolve_writes = [
        line.strip()
        for line in socket.splitlines()
        if "adjustWriteOpAfterResolve =" in line and "==" not in line
    ]
    direct_socket_connected_logged_writes = [
        line.strip()
        for line in socket.splitlines()
        if "mtproxySocketConnectedLogged =" in line and "==" not in line
    ]
    require(
        direct_endpoint_backoff_writes == ["proxyEndpointBackoffReady = ready;"],
        "proxyEndpointBackoffReady must be written only by setProxyEndpointBackoffReady",
        failures,
    )
    require(
        direct_endpoint_dns_writes == ["proxyEndpointDnsCoalesceReady = ready;"],
        "proxyEndpointDnsCoalesceReady must be written only by setProxyEndpointDnsCoalesceReady",
        failures,
    )
    require(
        direct_write_after_resolve_writes == ["adjustWriteOpAfterResolve = pending;"],
        "adjustWriteOpAfterResolve must be written only by setAdjustWriteOpAfterResolve",
        failures,
    )
    require(
        direct_socket_connected_logged_writes == ["mtproxySocketConnectedLogged = logged;"],
        "mtproxySocketConnectedLogged must be written only by setMtProxySocketConnectedLogged",
        failures,
    )
    host_resolve_body = method_body(socket, "void ConnectionSocket::requestPendingHostResolve", "void ConnectionSocket::onHostNameResolved")
    require(
        "if (!canStartHostResolve())" in host_resolve_body
        and 'setMtProxyDnsResolveAttemptStarted(true, "host_resolve_start")' in host_resolve_body
        and 'setMtProxyPreTcpWaitPhase("host_resolve_start"' in host_resolve_body
        and 'setTransportState(TransportState::WaitingGate, "host_resolve_start")' in host_resolve_body
        and "getHostByName(host, instanceNum, this)" in host_resolve_body,
        "requestPendingHostResolve must mark a real DNS start immediately before delegate host resolve",
        failures,
    )
    host_resolve_policy_body = method_body(socket, "bool ConnectionSocket::canStartHostResolve", "void ConnectionSocket::checkHostResolveCallback")
    require(
        "waitingForHostResolve.empty()" in host_resolve_policy_body
        and 'checkTransportActionRequirements("host_resolve_start")' in host_resolve_policy_body
        and 'logTransportInvariant("host_resolve_start"' in host_resolve_policy_body,
        "canStartHostResolve must guard pending host and pre-connect transport states",
        failures,
    )
    host_callback_body = method_body(socket, "void ConnectionSocket::onHostNameResolved", "void ConnectionSocket::setTimeout")
    require(
        'checkHostResolveCallback(host)' in host_callback_body
        and 'setMtProxyDnsResolveAttemptStarted(false, "host_resolve_callback")' in host_callback_body,
        "onHostNameResolved must run the transport-state callback check and clear the DNS attempt latch",
        failures,
    )
    host_callback_policy_body = method_body(socket, "void ConnectionSocket::checkHostResolveCallback", "void ConnectionSocket::clearPendingClientHello")
    require(
        'checkTransportActionRequirements("host_resolve_callback")' in host_callback_policy_body
        and 'logTransportInvariant("host_resolve_callback"' in host_callback_policy_body,
        "checkHostResolveCallback must log host resolve callbacks outside waiting_gate",
        failures,
    )
    wait_resolve_body = method_body(socket, "void ConnectionSocket::setWaitingForHostResolve", "bool ConnectionSocket::canNotifyConnected")
    require(
        "waitingForHostResolve = host;" in wait_resolve_body
        and "host_resolve_state_change" in wait_resolve_body
        and "waiting_resolve=%d" in wait_resolve_body
        and "transport_state=%s" in wait_resolve_body
        and "epoll_registered=%d" in wait_resolve_body,
        "waitingForHostResolve writes must be centralized and logged through setWaitingForHostResolve",
        failures,
    )
    direct_waiting_resolve_writes = [
        line.strip()
        for line in socket.splitlines()
        if "waitingForHostResolve =" in line and "==" not in line and "!=" not in line
    ]
    require(
        direct_waiting_resolve_writes == ["waitingForHostResolve = host;"],
        "waitingForHostResolve must be written only by setWaitingForHostResolve",
        failures,
    )
    notify_connected_policy_body = method_body(socket, "bool ConnectionSocket::canNotifyConnected", "void ConnectionSocket::clearPendingClientHello")
    require(
        "checkTransportActionRequirements(action)" in notify_connected_policy_body
        and "onConnectedSent" in notify_connected_policy_body
        and "logTransportInvariant(action" in notify_connected_policy_body,
        "canNotifyConnected must guard mtproto_ready state and duplicate connected callbacks",
        failures,
    )
    require(
        'if (!canNotifyConnected("wss_ready"))' in on_event_body
        and 'if (!canNotifyConnected("on_connected"))' in on_event_body,
        "WSS and generic connected callbacks must use the transport action policy",
        failures,
    )
    close_notified_body = method_body(socket, "void ConnectionSocket::setSocketCloseNotified", "void ConnectionSocket::setConnectedNotified")
    require(
        "socketCloseNotified = notified;" in close_notified_body
        and "socket_close_notify_state_change" in close_notified_body
        and "close_notified=%d" in close_notified_body
        and "transport_state=%s" in close_notified_body
        and "epoll_registered=%d" in close_notified_body,
        "socketCloseNotified writes must be centralized and logged through setSocketCloseNotified",
        failures,
    )
    direct_close_notified_writes = [
        line.strip()
        for line in socket.splitlines()
        if "socketCloseNotified =" in line and "==" not in line
    ]
    require(
        direct_close_notified_writes == ["socketCloseNotified = notified;"],
        "socketCloseNotified must be written only by setSocketCloseNotified",
        failures,
    )
    connected_notified_body = method_body(socket, "void ConnectionSocket::setConnectedNotified", "void ConnectionSocket::clearPendingClientHello")
    require(
        "onConnectedSent = sent;" in connected_notified_body
        and "connected_notify_state_change" in connected_notified_body
        and "connected_notified=%d" in connected_notified_body
        and "transport_state=%s" in connected_notified_body
        and "epoll_registered=%d" in connected_notified_body,
        "onConnectedSent writes must be centralized and logged through setConnectedNotified",
        failures,
    )
    direct_connected_writes = [
        line.strip()
        for line in socket.splitlines()
        if "onConnectedSent =" in line and "==" not in line
    ]
    require(
        direct_connected_writes == ["onConnectedSent = sent;"],
        "onConnectedSent must be written only by setConnectedNotified",
        failures,
    )
    received_data_policy_body = method_body(socket, "bool ConnectionSocket::canDeliverReceivedData", "void ConnectionSocket::clearPendingClientHello")
    require(
        "checkTransportActionRequirements(action)" in received_data_policy_body
        and "currentTransportWss" not in received_data_policy_body
        and "currentWssTransport" not in received_data_policy_body
        and "isReady()" not in received_data_policy_body,
        "canDeliverReceivedData must delegate MTProxy/WSS data delivery requirements to the action policy",
        failures,
    )
    dispatch_wss_body = method_body(socket, "bool ConnectionSocket::dispatchWssPayloads", "void ConnectionSocket::publishProxyConnectionStage")
    require(
        'canDeliverReceivedData("wss_payload_recv")' in dispatch_wss_body,
        "WSS payload dispatch must use the transport action policy before onReceivedData",
        failures,
    )
    wss_frame_policy_body = method_body(socket, "bool ConnectionSocket::canSendWssFrame", "void ConnectionSocket::clearPendingClientHello")
    require(
        'checkTransportActionRequirements("sendWssFrame")' in wss_frame_policy_body,
        "canSendWssFrame must delegate WSS mode/ready/fd/epoll checks to the action policy",
        failures,
    )
    require(
        "if (!canSendWssFrame())" in on_event_body
        and "currentWssTransport->sendFrame" in on_event_body,
        "WSS outbound frame send must use the transport action policy",
        failures,
    )
    write_raw_body = method_body(socket, "void ConnectionSocket::writeBuffer(uint8_t *data", "void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer)")
    write_buffer_body = method_body(socket, "void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer)", "void ConnectionSocket::adjustWriteOp")
    require(
        'canQueueOutboundBuffer("writeBufferRaw")' in write_raw_body,
        "raw writeBuffer must use the outbound queue transport action policy before allocating/appending",
        failures,
    )
    require(
        'canQueueOutboundBuffer("writeBuffer")' in write_buffer_body,
        "buffer writeBuffer must use the outbound queue transport action policy before appending",
        failures,
    )
    queue_policy_body = method_body(socket, "bool ConnectionSocket::canQueueOutboundBuffer", "void ConnectionSocket::clearPendingClientHello")
    require(
        "checkTransportActionRequirements(action)" in queue_policy_body,
        "canQueueOutboundBuffer must reject idle/closing writes and log invariants",
        failures,
    )
    send_raw_policy_body = method_body(socket, "bool ConnectionSocket::canSendRawSocketBytes", "bool ConnectionSocket::canReceiveRawSocketBytes")
    require(
        "checkTransportActionRequirements(action)" in send_raw_policy_body,
        "canSendRawSocketBytes must delegate raw send liveness/state checks to the shared action policy",
        failures,
    )
    recv_raw_policy_body = method_body(socket, "bool ConnectionSocket::canReceiveRawSocketBytes", "void ConnectionSocket::clearPendingClientHello")
    require(
        'checkTransportActionRequirements("raw_socket_recv")' in recv_raw_policy_body,
        "canReceiveRawSocketBytes must delegate raw recv liveness/state checks to the shared action policy",
        failures,
    )
    action_table_body = method_body(socket, "bool ConnectionSocket::isTransportStateAllowedForAction", "bool ConnectionSocket::canUseLiveEpollSocket")
    require(
        "findTransportActionRule(action)" in action_table_body,
        "isTransportStateAllowedForAction must use the shared action rule lookup",
        failures,
    )
    action_table_body = method_body(machine, "const ConnectionSocketStateMachine::ActionRule *ConnectionSocketStateMachine::findActionRule", "bool ConnectionSocketStateMachine::can")
    require(
        "ActionRule" in action_table_body
        and "rules[]" in action_table_body
        and "for (const ActionRule &rule : rules)" in action_table_body
        and "strcmp(action, rule.action) == 0" in action_table_body
        and "create_wss_socket" in action_table_body
        and "create_wss_ipv6_socket" in action_table_body
        and "create_proxy_socket" in action_table_body
        and "create_direct_socket" in action_table_body
        and "sendPendingClientHello" in action_table_body
        and "configure_socket" in action_table_body
        and "checkSocketError" in action_table_body
        and "onEvent" in action_table_body
        and "adjustWriteOp" in action_table_body
        and "closeSocket" in action_table_body
        and "closeSocket_cleanup" in action_table_body
        and "epoll_ctl_del" in action_table_body
        and "close_native_socket" in action_table_body
        and "releaseProxyHandshakeAdmission" in action_table_body
        and "writeBufferRaw" in action_table_body,
        "transport action states must be table-driven through allowedActionStates",
        failures,
    )
    for action in (
        "raw_client_hello_send",
        "raw_tls_frame_send",
        "raw_socks_method_send",
        "raw_socks_auth_send",
        "raw_socks_connect_send",
        "raw_plain_mtproto_send",
        "raw_socket_recv",
    ):
        require(
            action in action_table_body,
            f"{action} must be table-driven through allowedActionStates",
            failures,
        )
    epoll_event_policy_body = method_body(socket, "bool ConnectionSocket::canProcessEpollEvent", "void ConnectionSocket::checkCloseSocketAction")
    require(
        'checkTransportActionRequirements("onEvent")' in epoll_event_policy_body,
        "onEvent entry must be checked through the shared action requirements policy",
        failures,
    )
    action_requirements_body = method_body(socket, "bool ConnectionSocket::checkTransportActionRequirements", "bool ConnectionSocket::canUseLiveEpollSocket")
    require(
        "findTransportActionRule(action)" in action_requirements_body
        and "TransportSocketPolicy::LiveEpoll" in action_requirements_body
        and "TransportSocketPolicy::NoSocket" in action_requirements_body
        and "TransportSocketPolicy::OpenWithoutEpoll" in action_requirements_body
        and "expectedProxyAuthState" in action_requirements_body
        and "expectedTlsState" in action_requirements_body
        and "requireWssTransport" in action_requirements_body
        and "requireWssReady" in action_requirements_body
        and "logTransportInvariant(action" in action_requirements_body,
        "transport action requirements must centralize socket/proxy/tls/WSS predicates in the action policy",
        failures,
    )

    close_body = method_body(socket, "void ConnectionSocket::closeSocket", "void ConnectionSocket::onEvent")
    require(
        'checkCloseSocketAction("closeSocket")' in close_body
        and 'checkCloseSocketAction("closeSocket_cleanup")' in close_body
        and "canUnregisterEpollSocket()" in close_body
        and "canCloseNativeSocket()" in close_body
        and "stateMachine.epollCtlDel" in close_body
        and "stateMachine.closeNativeSocket" in close_body
        and 'setTransportState(TransportState::Closing, "closeSocket")' in close_body
        and 'setTransportState(TransportState::Idle, "closeSocket_cleanup")' in close_body
        and "transport_state=%s" in close_body
        and "epoll_registered=%d" in close_body,
        "closeSocket must be idempotent and log state before cleanup",
        failures,
    )
    require(
        "std::string terminalDiagnostic = deriveMtProxyTerminalDiagnostic(reason, error);" in close_body
        and "publishProxyConnectionStage(terminalDiagnostic.c_str())" in close_body
        and 'recordMtProxyEndpointFailure(terminalDiagnostic.c_str(), "closeSocket")' in close_body
        and "publishProxyConnectionStage(proxyCheckDiagnostic.c_str())" not in close_body
        and 'recordMtProxyEndpointFailure(proxyCheckDiagnostic.c_str(), "closeSocket")' not in close_body,
        "closeSocket must publish/record derived terminal diagnostics, not the mutable in-flight proxyCheckDiagnostic",
        failures,
    )
    close_policy_body = method_body(socket, "void ConnectionSocket::checkCloseSocketAction", "void ConnectionSocket::checkProxyHandshakeAdmissionRelease")
    require(
        "checkTransportActionRequirements(action)" in close_policy_body,
        "closeSocket enter/cleanup must be checked through the shared action requirements policy",
        failures,
    )
    epoll_delete_policy_body = method_body(socket, "bool ConnectionSocket::canUnregisterEpollSocket", "bool ConnectionSocket::canCloseNativeSocket")
    require(
        'checkTransportActionRequirements("epoll_ctl_del")' in epoll_delete_policy_body,
        "EPOLL_CTL_DEL must be checked through the shared action requirements policy",
        failures,
    )
    close_native_policy_body = method_body(socket, "bool ConnectionSocket::canCloseNativeSocket", "void ConnectionSocket::checkProxyHandshakeAdmissionRelease")
    require(
        'checkTransportActionRequirements("close_native_socket")' in close_native_policy_body,
        "native socket close must be checked through the shared action requirements policy",
        failures,
    )
    endpoint_failure_body = method_body(socket, "void ConnectionSocket::recordMtProxyEndpointFailure", "void ConnectionSocket::recordMtProxyEndpointHandshakeOk")
    require(
        "mtProxyDiagnosticIsLocalSchedulerTimeout" in endpoint_failure_body
        and "return;" in endpoint_failure_body,
        "native endpoint failure accounting must ignore local scheduler timeout phases",
        failures,
    )
    admission_state_body = method_body(socket, "void ConnectionSocket::setProxyHandshakeAdmissionState", "void ConnectionSocket::checkProxyHandshakeAdmissionRelease")
    require(
        "proxyHandshakeAdmissionQueued = nextQueued;" in admission_state_body
        and "proxyHandshakeAdmissionQueuePublished = nextPublished;" in admission_state_body
        and "proxyHandshakeAdmissionActive = nextActive;" in admission_state_body
        and "proxyHandshakeAdmissionReady = nextReady;" in admission_state_body
        and "admission_state_change" in admission_state_body
        and "admission_active=%d" in admission_state_body
        and "admission_queued=%d" in admission_state_body
        and "transport_state=%s" in admission_state_body
        and "epoll_registered=%d" in admission_state_body,
        "admission flags must be centralized and logged through setProxyHandshakeAdmissionState",
        failures,
    )
    direct_admission_writes = [
        line.strip()
        for line in socket.splitlines()
        if (
            "proxyHandshakeAdmissionQueued =" in line
            or "proxyHandshakeAdmissionQueuePublished =" in line
            or "proxyHandshakeAdmissionActive =" in line
            or "proxyHandshakeAdmissionReady =" in line
        )
        and "==" not in line
    ]
    require(
        direct_admission_writes == [
            "proxyHandshakeAdmissionQueued = nextQueued;",
            "proxyHandshakeAdmissionQueuePublished = nextPublished;",
            "proxyHandshakeAdmissionActive = nextActive;",
            "proxyHandshakeAdmissionReady = nextReady;",
        ],
        "admission flags must be written only by setProxyHandshakeAdmissionState",
        failures,
    )

    direct_state_writes = [
        line.strip()
        for line in socket.splitlines()
        if "currentTransportState =" in line and "==" not in line
    ]
    require(
        direct_state_writes == [],
        "currentTransportState must be written only by ConnectionSocketStateMachine::setLifecycle",
        failures,
    )

    transition_body = method_body(machine, "bool ConnectionSocketStateMachine::isAllowedTransition", "void ConnectionSocketStateMachine::setLifecycle")
    require(
        "LifecycleState::Idle" in transition_body
        and "LifecycleState::Prepared" in transition_body
        and "LifecycleState::WaitingGate" in transition_body
        and "LifecycleState::TcpConnecting" in transition_body
        and "LifecycleState::EpollRegistered" in transition_body
        and "LifecycleState::FakeTlsHandshake" in transition_body
        and "LifecycleState::MtprotoReady" in transition_body
        and "LifecycleState::Closing" in transition_body,
        "TransportState transitions must be explicit for every state",
        failures,
    )
    require(
        "transitions[]" in transition_body
        and "for (const auto &transition : transitions)" in transition_body
        and "switch (previous)" not in transition_body,
        "TransportState transitions must be table-driven rather than a switch over previous state",
        failures,
    )
    set_state_body = method_body(socket, "void ConnectionSocket::setTransportState", "void ConnectionSocket::logTransportSnapshot")
    require(
        "isAllowedTransportTransition(currentTransportState, next)" in set_state_body
        and 'logTransportInvariant("setTransportState", "invalid_transition")' in set_state_body,
        "setTransportState must check the transition table and log invalid transitions",
        failures,
    )
    require(
        "stateMachine.setLifecycle(next)" in set_state_body,
        "setTransportState must write lifecycle through ConnectionSocketStateMachine",
        failures,
    )
    proxy_transition_body = method_body(socket, "bool ConnectionSocket::isAllowedProxyAuthTransition", "void ConnectionSocket::setProxyAuthState")
    require(
        "ProxyAuthTransitionRule" in proxy_transition_body
        and "allowedTransitions[]" in proxy_transition_body
        and "for (const ProxyAuthTransitionRule &rule : allowedTransitions)" in proxy_transition_body
        and "previous == next" in proxy_transition_body
        and "{1, 2}" in proxy_transition_body
        and "{10, 11}" in proxy_transition_body,
        "proxyAuthState transitions must be table-driven instead of scattered direct writes",
        failures,
    )
    set_proxy_state_body = method_body(socket, "void ConnectionSocket::setProxyAuthState", "void ConnectionSocket::logTransportSnapshot")
    require(
        "isAllowedProxyAuthTransition(proxyAuthState, next)" in set_proxy_state_body
        and 'logTransportInvariant("setProxyAuthState", "invalid_transition")' in set_proxy_state_body
        and "stateMachine.setProxyAuthState(next)" in set_proxy_state_body
        and "proxy_state_from=%s" in set_proxy_state_body
        and "proxy_state_to=%s" in set_proxy_state_body,
        "setProxyAuthState must validate, log, and own proxyAuthState writes",
        failures,
    )
    direct_proxy_state_writes = [
        line.strip()
        for line in socket.splitlines()
        if "proxyAuthState =" in line and "==" not in line
    ]
    require(
        direct_proxy_state_writes == [],
        "proxyAuthState must be written only by ConnectionSocketStateMachine::setProxyAuthState",
        failures,
    )
    tls_transition_body = method_body(socket, "bool ConnectionSocket::isAllowedTlsStateTransition", "void ConnectionSocket::setTlsState")
    require(
        "TlsStateTransitionRule" in tls_transition_body
        and "allowedTransitions[]" in tls_transition_body
        and "for (const TlsStateTransitionRule &rule : allowedTransitions)" in tls_transition_body
        and "previous == next" in tls_transition_body
        and "next == 0" in tls_transition_body
        and "{0, 1}" in tls_transition_body
        and "{1, 2}" in tls_transition_body,
        "tlsState transitions must be table-driven instead of scattered direct writes",
        failures,
    )
    set_tls_state_body = method_body(socket, "void ConnectionSocket::setTlsState", "void ConnectionSocket::logTransportSnapshot")
    require(
        "isAllowedTlsStateTransition(tlsState, next)" in set_tls_state_body
        and 'logTransportInvariant("setTlsState", "invalid_transition")' in set_tls_state_body
        and "stateMachine.setTlsState(next)" in set_tls_state_body
        and "tls_state_from=%s" in set_tls_state_body
        and "tls_state_to=%s" in set_tls_state_body,
        "setTlsState must validate, log, and own tlsState writes",
        failures,
    )
    direct_tls_state_writes = [
        line.strip()
        for line in socket.splitlines()
        if "tlsState =" in line and "==" not in line
    ]
    require(
        direct_tls_state_writes == [],
        "tlsState must be written only by ConnectionSocketStateMachine::setTlsState",
        failures,
    )

    require(
        '"transport_invariant": "transport_invariant"' in analyzer
        and '"endpoint_handshake_ok": "endpoint_handshake_ok"' in analyzer
        and '"endpoint_data_path_success": "endpoint_data_path_success"' in analyzer
        and "transport_state" in analyzer,
        "MTProxy analyzer must recognize transport-state and split endpoint-success markers",
        failures,
    )

    if failures:
        print("MTProxy transport-state guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("MTProxy transport-state guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
