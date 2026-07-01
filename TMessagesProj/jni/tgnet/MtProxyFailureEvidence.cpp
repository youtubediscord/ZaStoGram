#include "MtProxyFailureEvidence.h"

#include "MtProxyPhaseContract.h"

MtProxyFailureEvidenceKind mtProxyEvidenceForPhase(const std::string &phase, size_t responseBytes) {
    if (phase.empty()) {
        return MtProxyFailureEvidenceKind::None;
    }
    if (phase == MtProxyPhase::ConnectionNotStarted
            || phase == MtProxyPhase::AdmissionTimeout
            || phase == MtProxyPhase::EndpointCooldownTimeout
            || phase == MtProxyPhase::MtproxyProbeWaitTimeout
            || phase == MtProxyPhase::DnsCoalesceTimeout
            || phase == MtProxyPhase::TcpConnectGateTimeout) {
        return MtProxyFailureEvidenceKind::PreTcpLocalWait;
    }
    if (phase == MtProxyPhase::DnsNegativeCacheHit
            || phase == MtProxyPhase::DnsBlockedZeroAddress
            || phase == MtProxyPhase::HostResolveFailed
            || phase == MtProxyPhase::HostResolveTimeout) {
        return MtProxyFailureEvidenceKind::DnsFailure;
    }
    if (phase == MtProxyPhase::TcpNotConnected
            || phase == MtProxyPhase::TcpConnectionRefused
            || phase == MtProxyPhase::TcpConnectTimeout
            || phase == MtProxyPhase::TcpConnectedNoPong) {
        return MtProxyFailureEvidenceKind::TcpFailure;
    }
    if (phase == MtProxyPhase::FaketlsServerHelloWaitTimeout
            || phase == "true_client_hello_timeout"
            || phase == "client_hello_sent_no_server_hello") {
        return MtProxyFailureEvidenceKind::NoBytesAfterClientHello;
    }
    if (phase == MtProxyPhase::ServerClosedAfterClientHello) {
        return responseBytes == 0
                ? MtProxyFailureEvidenceKind::NoBytesAfterClientHello
                : MtProxyFailureEvidenceKind::ServerBytesParserFailure;
    }
    if (phase == MtProxyPhase::TlsAlertAfterClientHello
            || phase == MtProxyPhase::ShortTlsResponseAfterClientHello
            || phase == MtProxyPhase::UnrecognizedResponseAfterClientHello
            || phase == "unrecognized_tls_response_after_client_hello") {
        return MtProxyFailureEvidenceKind::ServerBytesParserFailure;
    }
    if (phase == MtProxyPhase::ServerHelloHmacMismatch) {
        return MtProxyFailureEvidenceKind::ServerHelloHmacMismatch;
    }
    if (phase == MtProxyPhase::PostHandshakeNoAppdata
            || phase == MtProxyPhase::MtproxyPacketSentNoResponse
            || phase == MtProxyPhase::DroppedEarlyAfterAppdata
            || phase == MtProxyPhase::DroppedAfterAppdata) {
        return MtProxyFailureEvidenceKind::PostHandshakeNoAppData;
    }
    if (phase == MtProxyPhase::SecretParseInvalidDomainControlChar
            || phase == MtProxyPhase::SecretParseInvalidDomain) {
        return MtProxyFailureEvidenceKind::ConfigInvalidSecret;
    }
    if (phase == MtProxyPhase::BackgroundHandshakeAborted
            || phase == MtProxyPhase::ShadowedSocketFailure
            || phase == MtProxyPhase::IgnoredCancelledGeneration) {
        return MtProxyFailureEvidenceKind::CancelledOrShadowed;
    }
    return MtProxyFailureEvidenceKind::None;
}

const char *mtProxyFailureEvidenceName(MtProxyFailureEvidenceKind kind) {
    switch (kind) {
        case MtProxyFailureEvidenceKind::PreTcpLocalWait:
            return "pre_tcp_local_wait";
        case MtProxyFailureEvidenceKind::DnsFailure:
            return "dns_failure";
        case MtProxyFailureEvidenceKind::TcpFailure:
            return "tcp_failure";
        case MtProxyFailureEvidenceKind::NoBytesAfterClientHello:
            return "no_bytes_after_client_hello";
        case MtProxyFailureEvidenceKind::ServerBytesParserFailure:
            return "server_bytes_parser_failure";
        case MtProxyFailureEvidenceKind::ServerHelloHmacMismatch:
            return "server_hello_hmac_mismatch";
        case MtProxyFailureEvidenceKind::PostHandshakeNoAppData:
            return "post_handshake_no_app_data";
        case MtProxyFailureEvidenceKind::ConfigInvalidSecret:
            return "config_invalid_secret";
        case MtProxyFailureEvidenceKind::CancelledOrShadowed:
            return "cancelled_or_shadowed";
        case MtProxyFailureEvidenceKind::None:
        default:
            return "none";
    }
}
