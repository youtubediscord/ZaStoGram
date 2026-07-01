#ifndef MTPROXYPHASECONTRACT_H
#define MTPROXYPHASECONTRACT_H

namespace MtProxyPhase {
constexpr const char *AdmissionQueue = "admission_queue";
constexpr const char *EndpointCooldown = "endpoint_cooldown";
constexpr const char *TcpConnectGate = "tcp_connect_gate";
constexpr const char *DnsCoalesceWait = "dns_coalesce_wait";
constexpr const char *DnsCacheHit = "dns_cache_hit";
constexpr const char *DnsCacheStore = "dns_cache_store";
constexpr const char *MtproxyProbeWait = "mtproxy_probe_wait";
constexpr const char *PhaseAdaptiveRecipe = "phase_adaptive_recipe";
constexpr const char *SecretDomainSanitized = "secret_domain_sanitized";
constexpr const char *HostResolveStart = "host_resolve_start";
constexpr const char *ConnectStart = "connect_start";
constexpr const char *SocketConnectStart = "socket_connect_start";
constexpr const char *SocketConnected = "socket_connected";
constexpr const char *ClientHelloSent = "client_hello_sent";
constexpr const char *AdmissionHoldAfterClientHelloFailure = "admission_hold_after_client_hello_failure";
constexpr const char *ServerHelloHmacOk = "server_hello_hmac_ok";
constexpr const char *OnConnected = "on_connected";
constexpr const char *FirstTlsAppSent = "first_tls_app_sent";
constexpr const char *FirstMtproxyPacketSent = "first_mtproxy_packet_sent";
constexpr const char *ConnectionNotStarted = "connection_not_started";
constexpr const char *AdmissionTimeout = "admission_timeout";
constexpr const char *EndpointCooldownTimeout = "endpoint_cooldown_timeout";
constexpr const char *MtproxyProbeWaitTimeout = "mtproxy_probe_wait_timeout";
constexpr const char *DnsCoalesceTimeout = "dns_coalesce_timeout";
constexpr const char *DnsNegativeCacheHit = "dns_negative_cache_hit";
constexpr const char *DnsBlockedZeroAddress = "dns_blocked_zero_address";
constexpr const char *HostResolveFailed = "host_resolve_failed";
constexpr const char *HostResolveTimeout = "host_resolve_timeout";
constexpr const char *TcpConnectGateTimeout = "tcp_connect_gate_timeout";
constexpr const char *TcpNotConnected = "tcp_not_connected";
constexpr const char *TcpConnectionRefused = "tcp_connection_refused";
constexpr const char *TcpConnectTimeout = "tcp_connect_timeout";
constexpr const char *TcpConnectedNoPong = "tcp_connected_no_pong";
constexpr const char *SecretParseInvalidDomainControlChar = "secret_parse_invalid_domain_control_char";
constexpr const char *SecretParseInvalidDomain = "secret_parse_invalid_domain";
constexpr const char *FaketlsServerHelloWaitTimeout = "faketls_server_hello_wait_timeout";
constexpr const char *ServerClosedAfterClientHello = "server_closed_after_client_hello";
constexpr const char *TlsAlertAfterClientHello = "tls_alert_after_client_hello";
constexpr const char *ShortTlsResponseAfterClientHello = "short_tls_response_after_client_hello";
constexpr const char *UnrecognizedResponseAfterClientHello = "unrecognized_response_after_client_hello";
constexpr const char *ServerHelloHmacMismatch = "server_hello_hmac_mismatch";
constexpr const char *BackgroundHandshakeAborted = "background_handshake_aborted";
constexpr const char *HandshakeProfilesExhausted = "handshake_profiles_exhausted";
constexpr const char *MtproxyPacketSentNoResponse = "mtproxy_packet_sent_no_response";
constexpr const char *PostHandshakeNoAppdata = "post_handshake_no_appdata";
constexpr const char *DroppedEarlyAfterAppdata = "dropped_early_after_appdata";
constexpr const char *DroppedAfterAppdata = "dropped_after_appdata";
constexpr const char *FirstTlsAppRecv = "first_tls_app_recv";
constexpr const char *FirstMtproxyPacketRecv = "first_mtproxy_packet_recv";
constexpr const char *ShadowedSocketFailure = "shadowed_socket_failure";
constexpr const char *IgnoredCancelledGeneration = "ignored_cancelled_generation";
constexpr const char *ReconnectBackoffSuppressed = "reconnect_backoff_suppressed";
}

#endif
