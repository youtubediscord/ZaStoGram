/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyStartupTimeline.h"

void MtProxyStartupTimeline::reset() {
    phase_ = MtProxyStartupPhase::None;
    localWaitDeadlineMs_ = 0;
    dnsResolveAttemptStarted_ = false;
    dnsResolveStartTimeMs_ = 0;
    dnsResolveDeadlineMs_ = 0;
    tcpConnectAttemptStarted_ = false;
    tcpConnectStartTimeMs_ = 0;
    tcpConnectDeadlineMs_ = 0;
}

void MtProxyStartupTimeline::beginLocalWait(MtProxyStartupPhase phase, int64_t deadlineMs) {
    phase_ = phase;
    localWaitDeadlineMs_ = deadlineMs;
}

void MtProxyStartupTimeline::finishLocalWait() {
    if (!isLocalWaitPhase(phase_)) {
        return;
    }
    phase_ = MtProxyStartupPhase::None;
    localWaitDeadlineMs_ = 0;
}

void MtProxyStartupTimeline::beginDnsResolve(int64_t nowMs, time_t timeoutSeconds) {
    finishLocalWait();
    phase_ = MtProxyStartupPhase::HostResolve;
    dnsResolveAttemptStarted_ = true;
    dnsResolveStartTimeMs_ = nowMs;
    dnsResolveDeadlineMs_ = deadlineFromTimeout(nowMs, timeoutSeconds);
}

void MtProxyStartupTimeline::finishDnsResolve() {
    if (phase_ == MtProxyStartupPhase::HostResolve) {
        phase_ = MtProxyStartupPhase::None;
    }
    dnsResolveAttemptStarted_ = false;
    dnsResolveStartTimeMs_ = 0;
    dnsResolveDeadlineMs_ = 0;
}

void MtProxyStartupTimeline::beginTcpConnect(int64_t nowMs, time_t timeoutSeconds) {
    finishLocalWait();
    finishDnsResolve();
    phase_ = MtProxyStartupPhase::TcpConnect;
    tcpConnectAttemptStarted_ = true;
    tcpConnectStartTimeMs_ = nowMs;
    tcpConnectDeadlineMs_ = deadlineFromTimeout(nowMs, timeoutSeconds);
}

void MtProxyStartupTimeline::finishTcpConnect() {
    if (phase_ == MtProxyStartupPhase::TcpConnect) {
        phase_ = MtProxyStartupPhase::None;
    }
    tcpConnectAttemptStarted_ = false;
    tcpConnectStartTimeMs_ = 0;
    tcpConnectDeadlineMs_ = 0;
}

MtProxyStartupTimeoutDecision MtProxyStartupTimeline::timeoutDecision(int64_t nowMs, bool socketConnectedLogged) const {
    MtProxyStartupTimeoutDecision decision;
    decision.phase = phase_;
    if (tcpConnectAttemptStarted_ && !socketConnectedLogged) {
        decision.active = true;
        decision.diagnostic = "tcp_connect_timeout";
        decision.event = "tcp_connect_timeout";
        decision.startMs = tcpConnectStartTimeMs_;
        decision.deadlineMs = tcpConnectDeadlineMs_;
    } else if (dnsResolveAttemptStarted_) {
        decision.active = true;
        decision.diagnostic = "host_resolve_timeout";
        decision.event = "host_resolve_timeout";
        decision.startMs = dnsResolveStartTimeMs_;
        decision.deadlineMs = dnsResolveDeadlineMs_;
    } else if (isLocalWaitPhase(phase_)) {
        decision.active = true;
        decision.diagnostic = timeoutDiagnosticForPhase(phase_);
        decision.event = "pre_tcp_timeout";
        decision.startMs = 0;
        decision.deadlineMs = localWaitDeadlineMs_;
    }
    if (!decision.active) {
        return decision;
    }
    if (decision.deadlineMs <= 0 || nowMs <= decision.deadlineMs) {
        return decision;
    }
    decision.expired = true;
    if (decision.startMs > 0 && nowMs >= decision.startMs) {
        decision.elapsedMs = nowMs - decision.startMs;
    } else if (decision.deadlineMs > 0 && nowMs >= decision.deadlineMs) {
        decision.elapsedMs = nowMs - decision.deadlineMs;
    }
    return decision;
}

const char *MtProxyStartupTimeline::terminalDiagnostic(bool socketConnectedLogged) const {
    if (tcpConnectAttemptStarted_ && !socketConnectedLogged) {
        return "tcp_not_connected";
    }
    if (dnsResolveAttemptStarted_) {
        return "host_resolve_timeout";
    }
    if (isLocalWaitPhase(phase_)) {
        return timeoutDiagnosticForPhase(phase_);
    }
    return "connection_not_started";
}

MtProxyStartupTimerDecision MtProxyStartupTimeline::canRunPreTcpTimer(MtProxyStartupTimerKind expectedKind,
                                                                       uint32_t timerGeneration,
                                                                       uint32_t currentGeneration,
                                                                       MtProxyStartupTimerKind currentKind,
                                                                       bool socketAlive,
                                                                       bool waitingGate,
                                                                       bool epollRegistered) const {
    MtProxyStartupTimerDecision decision;
    if (timerGeneration != currentGeneration) {
        decision.ignoreReason = "generation";
    } else if (currentKind != expectedKind) {
        decision.ignoreReason = "mode";
    } else if (!socketAlive) {
        decision.ignoreReason = "socket_closed";
    } else if (!waitingGate) {
        decision.ignoreReason = "state";
    } else if (dnsResolveAttemptStarted_) {
        decision.ignoreReason = "dns_started";
    } else if (tcpConnectAttemptStarted_) {
        decision.ignoreReason = "tcp_started";
    } else if (epollRegistered) {
        decision.ignoreReason = "epoll_registered";
    } else if (!hasLocalWait()) {
        decision.ignoreReason = "phase";
    } else {
        decision.canRun = true;
    }
    return decision;
}

MtProxyStartupPhase MtProxyStartupTimeline::phase() const {
    return phase_;
}

const char *MtProxyStartupTimeline::phaseName() const {
    return phaseName(phase_);
}

const char *MtProxyStartupTimeline::phaseName(MtProxyStartupPhase phase) {
    switch (phase) {
        case MtProxyStartupPhase::None:
            return "";
        case MtProxyStartupPhase::AdmissionQueue:
            return "admission_queue";
        case MtProxyStartupPhase::EndpointCooldown:
            return "endpoint_cooldown";
        case MtProxyStartupPhase::ProbeWait:
            return "mtproxy_probe_wait";
        case MtProxyStartupPhase::DnsCoalesceWait:
            return "dns_coalesce_wait";
        case MtProxyStartupPhase::TcpConnectGate:
            return "tcp_connect_gate";
        case MtProxyStartupPhase::HostResolve:
            return "host_resolve_start";
        case MtProxyStartupPhase::TcpConnect:
            return "tcp_connect";
    }
    return "";
}

const char *MtProxyStartupTimeline::timerKindName(MtProxyStartupTimerKind kind) {
    switch (kind) {
        case MtProxyStartupTimerKind::None:
            return "none";
        case MtProxyStartupTimerKind::Admission:
            return "admission";
        case MtProxyStartupTimerKind::HostResolveAdmission:
            return "host_resolve_admission";
        case MtProxyStartupTimerKind::EndpointBackoff:
            return "endpoint_backoff";
        case MtProxyStartupTimerKind::ProbeWait:
            return "probe_wait";
        case MtProxyStartupTimerKind::DnsCoalesce:
            return "dns_coalesce";
        case MtProxyStartupTimerKind::TcpConnectGate:
            return "tcp_connect_gate";
    }
    return "unknown";
}

bool MtProxyStartupTimeline::hasLocalWait() const {
    return isLocalWaitPhase(phase_);
}

bool MtProxyStartupTimeline::dnsResolveAttemptStarted() const {
    return dnsResolveAttemptStarted_;
}

bool MtProxyStartupTimeline::tcpConnectAttemptStarted() const {
    return tcpConnectAttemptStarted_;
}

int64_t MtProxyStartupTimeline::localWaitDeadlineMs() const {
    return localWaitDeadlineMs_;
}

int64_t MtProxyStartupTimeline::dnsResolveStartTimeMs() const {
    return dnsResolveStartTimeMs_;
}

int64_t MtProxyStartupTimeline::dnsResolveDeadlineMs() const {
    return dnsResolveDeadlineMs_;
}

int64_t MtProxyStartupTimeline::tcpConnectStartTimeMs() const {
    return tcpConnectStartTimeMs_;
}

int64_t MtProxyStartupTimeline::tcpConnectDeadlineMs() const {
    return tcpConnectDeadlineMs_;
}

bool MtProxyStartupTimeline::isLocalWaitPhase(MtProxyStartupPhase phase) {
    return phase == MtProxyStartupPhase::AdmissionQueue
            || phase == MtProxyStartupPhase::EndpointCooldown
            || phase == MtProxyStartupPhase::ProbeWait
            || phase == MtProxyStartupPhase::DnsCoalesceWait
            || phase == MtProxyStartupPhase::TcpConnectGate;
}

int64_t MtProxyStartupTimeline::deadlineFromTimeout(int64_t nowMs, time_t timeoutSeconds) {
    if (timeoutSeconds == 0) {
        return 0;
    }
    return nowMs + (int64_t) timeoutSeconds * 1000;
}

const char *MtProxyStartupTimeline::timeoutDiagnosticForPhase(MtProxyStartupPhase phase) {
    switch (phase) {
        case MtProxyStartupPhase::AdmissionQueue:
            return "admission_timeout";
        case MtProxyStartupPhase::EndpointCooldown:
            return "endpoint_cooldown_timeout";
        case MtProxyStartupPhase::ProbeWait:
            return "mtproxy_probe_wait_timeout";
        case MtProxyStartupPhase::DnsCoalesceWait:
            return "dns_coalesce_timeout";
        case MtProxyStartupPhase::TcpConnectGate:
            return "tcp_connect_gate_timeout";
        case MtProxyStartupPhase::HostResolve:
            return "host_resolve_timeout";
        case MtProxyStartupPhase::TcpConnect:
            return "tcp_connect_timeout";
        case MtProxyStartupPhase::None:
            return "connection_not_started";
    }
    return "connection_not_started";
}

const char *MtProxyStartupTimeline::timeoutEventForPhase(MtProxyStartupPhase phase) {
    switch (phase) {
        case MtProxyStartupPhase::TcpConnect:
            return "tcp_connect_timeout";
        case MtProxyStartupPhase::HostResolve:
            return "host_resolve_timeout";
        case MtProxyStartupPhase::AdmissionQueue:
        case MtProxyStartupPhase::EndpointCooldown:
        case MtProxyStartupPhase::ProbeWait:
        case MtProxyStartupPhase::DnsCoalesceWait:
        case MtProxyStartupPhase::TcpConnectGate:
            return "pre_tcp_timeout";
        case MtProxyStartupPhase::None:
            return "connection_not_started";
    }
    return "connection_not_started";
}
