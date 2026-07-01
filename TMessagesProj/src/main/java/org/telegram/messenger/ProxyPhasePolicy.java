package org.telegram.messenger;

public final class ProxyPhasePolicy {
    public enum Kind {
        NEUTRAL,
        LIVE,
        SUCCESS,
        FAILURE
    }

    public enum KeyScope {
        NONE,
        EXACT,
        NETWORK
    }

    private static final PhaseInfo NEUTRAL_NONE = new PhaseInfo(Kind.NEUTRAL, KeyScope.NONE, false, false, true, false, false);

    private ProxyPhasePolicy() {
    }

    public static Kind kind(String phase) {
        return classify(phase).kind;
    }

    public static KeyScope keyScope(String phase) {
        return classify(phase).keyScope;
    }

    public static boolean canBackoff(String phase) {
        return classify(phase).canBackoff;
    }

    public static boolean canRotate(String phase) {
        return classify(phase).canRotate;
    }

    public static boolean isPunitiveFailure(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
            case ProxyCheckDiagnostics.HANDSHAKE_PROFILES_EXHAUSTED:
            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
            case ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA:
            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
                return true;
            default:
                return false;
        }
    }

    public static boolean isLocalOrLiveNonPunitive(String phase) {
        return isLivePhase(phase)
                || !canBackoff(phase)
                || (!canRotate(phase) && !terminalExactConfig(phase));
    }

    public static boolean canOverwriteVisible(String phase) {
        return classify(phase).canOverwriteVisible;
    }

    public static boolean usableSuccess(String phase) {
        return classify(phase).usableSuccess;
    }

    public static boolean terminalExactConfig(String phase) {
        return isTerminalExactConfigPhase(phase);
    }

    public static boolean isLivePhase(String phase) {
        Kind kind = kind(phase);
        return kind == Kind.LIVE || kind == Kind.SUCCESS;
    }

    public static boolean isFailure(String phase) {
        return kind(phase) == Kind.FAILURE;
    }

    public static boolean isOneShotTerminal(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return true;
            default:
                return false;
        }
    }

    public static String evidenceForPhase(String phase) {
        return failureClassForPhase(phase);
    }

    public static String failureClassForPhase(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
            case ProxyCheckDiagnostics.ADMISSION_TIMEOUT:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN_TIMEOUT:
            case ProxyCheckDiagnostics.DNS_COALESCE_TIMEOUT:
            case ProxyCheckDiagnostics.CONNECTING_TIMEOUT:
            case ProxyCheckDiagnostics.START_FAILED:
                return ProxyEndpointVerdict.FAILURE_CLASS_WAIT_TIMEOUT;

            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT_TIMEOUT:
                return ProxyEndpointVerdict.FAILURE_CLASS_PROBE_WAIT_TIMEOUT;

            case ProxyCheckDiagnostics.TCP_CONNECT_GATE_TIMEOUT:
                return ProxyEndpointVerdict.FAILURE_CLASS_TCP_GATE_WAIT_TIMEOUT;

            case ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT:
            case ProxyCheckDiagnostics.DNS_BLOCKED_ZERO_ADDRESS:
            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
                return ProxyEndpointVerdict.FAILURE_CLASS_DNS_FAILED;

            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED:
                return ProxyEndpointVerdict.FAILURE_CLASS_TCP_FAILED;

            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
                return ProxyEndpointVerdict.FAILURE_CLASS_TCP_REFUSED;

            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
                return ProxyEndpointVerdict.FAILURE_CLASS_TCP_TIMEOUT;

            case ProxyCheckDiagnostics.TRUE_CLIENT_HELLO_TIMEOUT:
            case ProxyCheckDiagnostics.FAKETLS_SERVER_HELLO_WAIT_TIMEOUT:
            case ProxyCheckDiagnostics.SERVER_CLOSED_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
                return ProxyEndpointVerdict.FAILURE_CLASS_FAKETLS_NO_SERVER_HELLO;

            case ProxyCheckDiagnostics.HANDSHAKE_PROFILES_EXHAUSTED:
            case ProxyCheckDiagnostics.TLS_ALERT_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SHORT_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
                return ProxyEndpointVerdict.FAILURE_CLASS_FAKETLS_BAD_SERVER_FLIGHT;

            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
            case ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA:
                return ProxyEndpointVerdict.FAILURE_CLASS_MTPROXY_NO_RESPONSE_AFTER_SEND;

            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
            case ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA:
                return ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED;

            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return ProxyEndpointVerdict.FAILURE_CLASS_SECRET_INVALID;

            case ProxyCheckDiagnostics.IGNORED_CANCELLED_GENERATION:
                return ProxyEndpointVerdict.FAILURE_CLASS_STALE_GENERATION_CANCELLED;

            case ProxyCheckDiagnostics.CANCELLED:
            case ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED:
            case ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE:
                return ProxyEndpointVerdict.FAILURE_CLASS_LIFECYCLE_CANCELLED;

            default:
                return ProxyEndpointVerdict.FAILURE_CLASS_NONE;
        }
    }

    public static ProxyEndpointVerdict verdictForPhase(String phase, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(phase);
        PhaseInfo info = classify(normalized);
        String failureClass = failureClassForPhase(normalized);
        if (ProxyEndpointVerdict.FAILURE_CLASS_NONE.equals(failureClass) && info.kind == Kind.FAILURE) {
            failureClass = ProxyEndpointVerdict.FAILURE_CLASS_UNKNOWN_FAILURE;
        } else if (ProxyEndpointVerdict.FAILURE_CLASS_NONE.equals(failureClass) && info.kind == Kind.SUCCESS) {
            failureClass = ProxyEndpointVerdict.FAILURE_CLASS_SUCCESS;
        } else if (ProxyEndpointVerdict.FAILURE_CLASS_NONE.equals(failureClass) && info.kind == Kind.LIVE) {
            failureClass = ProxyEndpointVerdict.FAILURE_CLASS_LIVE;
        }
        long stickyUntilMs = info.kind == Kind.FAILURE && now > 0
                ? now + ProxyCheckDiagnostics.freshFailureHoldEarlyRetryMs()
                : 0;
        return new ProxyEndpointVerdict(
                normalized,
                layerForPhase(normalized),
                failureClass,
                confidenceForPhase(normalized, info),
                actionForPhase(normalized, info),
                stickyUntilMs,
                userTextKeyForVerdict(normalized, failureClass, info),
                "",
                "",
                0,
                ProxyConnectionEvent.Origin.ACTIVE_SOCKET,
                info.kind,
                info.keyScope,
                info.canBackoff,
                info.canRotate,
                info.canOverwriteVisible,
                info.usableSuccess,
                info.terminalExactConfig);
    }

    public static ProxyEndpointVerdict verdictForEvent(ProxyConnectionEvent event) {
        ProxyEndpointVerdict verdict = verdictForPhase(event == null ? null : event.phase, event == null ? 0 : event.timestamp);
        if (event == null) {
            return verdict;
        }
        return verdict.withIdentity(event.endpointKey, event.networkKey, event.activationGeneration, event.origin);
    }

    public static ProxyEndpointVerdict postSuccessDataPathVerdict(ProxyEndpointVerdict verdict) {
        if (verdict == null) {
            return verdictForPhase(ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA, 0);
        }
        return verdict.withClassification(
                ProxyEndpointVerdict.LAYER_POST_HANDSHAKE_DATA,
                ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED,
                userTextKeyForFailureClass(ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED, verdict.phase));
    }

    public static boolean shouldAccelerateProxyRotation(String phase) {
        return canRotate(phase);
    }

    public static boolean isProxyUsableSuccessPhase(String phase) {
        return usableSuccess(phase);
    }

    private static PhaseInfo classify(String phase) {
        // Coordinator-owned exact phases: mtproxy_probe_wait, mtproxy_probe_wait_timeout,
        // faketls_server_hello_wait_timeout, server_closed_after_client_hello,
        // unrecognized_response_after_client_hello.
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.OK:
            case ProxyCheckDiagnostics.CHECKING:
            case ProxyCheckDiagnostics.CANCELLED:
            case ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE:
            case ProxyCheckDiagnostics.IGNORED_CANCELLED_GENERATION:
                return NEUTRAL_NONE;

            case ProxyCheckDiagnostics.ADMISSION_QUEUE:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN:
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT:
            case ProxyCheckDiagnostics.PHASE_ADAPTIVE_RECIPE:
            case ProxyCheckDiagnostics.SECRET_DOMAIN_SANITIZED:
            case ProxyCheckDiagnostics.CONNECT_START:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT:
            case ProxyCheckDiagnostics.ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_OK:
            case ProxyCheckDiagnostics.ON_CONNECTED:
            case ProxyCheckDiagnostics.FIRST_TLS_APP_SENT:
                return live(KeyScope.EXACT);

            case ProxyCheckDiagnostics.TCP_CONNECT_GATE:
            case ProxyCheckDiagnostics.DNS_COALESCE_WAIT:
            case ProxyCheckDiagnostics.DNS_CACHE_HIT:
            case ProxyCheckDiagnostics.DNS_CACHE_STORE:
            case ProxyCheckDiagnostics.HOST_RESOLVE_START:
            case ProxyCheckDiagnostics.SOCKET_CONNECT_START:
            case ProxyCheckDiagnostics.SOCKET_CONNECTED:
            case ProxyCheckDiagnostics.WAITING_TCP:
                return live(KeyScope.NETWORK);

            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_SENT:
                return live(KeyScope.EXACT);

            case ProxyCheckDiagnostics.FIRST_TLS_APP_RECV:
                return success(KeyScope.EXACT);

            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_RECV:
                return success(KeyScope.EXACT);

            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
                return failure(KeyScope.NONE, false, false);

            case ProxyCheckDiagnostics.ADMISSION_TIMEOUT:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN_TIMEOUT:
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT_TIMEOUT:
                return failure(KeyScope.EXACT, false, false);

            case ProxyCheckDiagnostics.TCP_CONNECT_GATE_TIMEOUT:
            case ProxyCheckDiagnostics.DNS_COALESCE_TIMEOUT:
            case ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT:
            case ProxyCheckDiagnostics.DNS_BLOCKED_ZERO_ADDRESS:
                return failure(KeyScope.NETWORK, false, false);

            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return failure(KeyScope.EXACT, true, true);

            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED:
            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
                return failure(KeyScope.NETWORK, true, true);

            case ProxyCheckDiagnostics.TRUE_CLIENT_HELLO_TIMEOUT:
            case ProxyCheckDiagnostics.FAKETLS_SERVER_HELLO_WAIT_TIMEOUT:
            case ProxyCheckDiagnostics.SERVER_CLOSED_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
            case ProxyCheckDiagnostics.TLS_ALERT_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SHORT_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
            case ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED:
                return failure(KeyScope.EXACT, false, false);

            case ProxyCheckDiagnostics.HANDSHAKE_PROFILES_EXHAUSTED:
                return failure(KeyScope.EXACT, true, true);

            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
            case ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA:
            case ProxyCheckDiagnostics.CONNECTING_TIMEOUT:
                return failure(KeyScope.EXACT, true, true);

            case ProxyCheckDiagnostics.UNKNOWN_FAIL:
                return failure(KeyScope.EXACT, true, false);

            case ProxyCheckDiagnostics.START_FAILED:
                return failure(KeyScope.NONE, false, false);

            case ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA:
                return failure(KeyScope.EXACT, false, false);

            default:
                return failure(KeyScope.EXACT, true, false);
        }
    }

    private static boolean isTerminalExactConfigPhase(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return true;
            default:
                return false;
        }
    }

    private static String layerForPhase(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.OK:
            case ProxyCheckDiagnostics.CHECKING:
            case ProxyCheckDiagnostics.WAITING_TCP:
                return ProxyEndpointVerdict.LAYER_SCHEDULER_LOCAL;

            case ProxyCheckDiagnostics.CANCELLED:
            case ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE:
            case ProxyCheckDiagnostics.IGNORED_CANCELLED_GENERATION:
            case ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED:
                return ProxyEndpointVerdict.LAYER_LIFECYCLE_CANCELLED;

            case ProxyCheckDiagnostics.ADMISSION_QUEUE:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN:
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT:
            case ProxyCheckDiagnostics.PHASE_ADAPTIVE_RECIPE:
            case ProxyCheckDiagnostics.SECRET_DOMAIN_SANITIZED:
            case ProxyCheckDiagnostics.CONNECT_START:
            case ProxyCheckDiagnostics.ADMISSION_TIMEOUT:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN_TIMEOUT:
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT_TIMEOUT:
            case ProxyCheckDiagnostics.DNS_COALESCE_WAIT:
            case ProxyCheckDiagnostics.DNS_COALESCE_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_CONNECT_GATE:
            case ProxyCheckDiagnostics.TCP_CONNECT_GATE_TIMEOUT:
            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
            case ProxyCheckDiagnostics.CONNECTING_TIMEOUT:
            case ProxyCheckDiagnostics.START_FAILED:
                return ProxyEndpointVerdict.LAYER_SCHEDULER_LOCAL;

            case ProxyCheckDiagnostics.DNS_CACHE_HIT:
            case ProxyCheckDiagnostics.DNS_CACHE_STORE:
            case ProxyCheckDiagnostics.HOST_RESOLVE_START:
            case ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT:
            case ProxyCheckDiagnostics.DNS_BLOCKED_ZERO_ADDRESS:
            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
                return ProxyEndpointVerdict.LAYER_DNS;

            case ProxyCheckDiagnostics.SOCKET_CONNECT_START:
            case ProxyCheckDiagnostics.SOCKET_CONNECTED:
            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED:
                return ProxyEndpointVerdict.LAYER_TCP;

            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT:
            case ProxyCheckDiagnostics.ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_OK:
            case ProxyCheckDiagnostics.TRUE_CLIENT_HELLO_TIMEOUT:
            case ProxyCheckDiagnostics.FAKETLS_SERVER_HELLO_WAIT_TIMEOUT:
            case ProxyCheckDiagnostics.SERVER_CLOSED_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
            case ProxyCheckDiagnostics.TLS_ALERT_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SHORT_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_TLS_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
            case ProxyCheckDiagnostics.HANDSHAKE_PROFILES_EXHAUSTED:
                return ProxyEndpointVerdict.LAYER_FAKETLS_HANDSHAKE;

            case ProxyCheckDiagnostics.ON_CONNECTED:
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_SENT:
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_RECV:
            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
                return ProxyEndpointVerdict.LAYER_MTPROXY_PLAIN;

            case ProxyCheckDiagnostics.FIRST_TLS_APP_SENT:
            case ProxyCheckDiagnostics.FIRST_TLS_APP_RECV:
            case ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA:
            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
            case ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA:
                return ProxyEndpointVerdict.LAYER_POST_HANDSHAKE_DATA;

            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return ProxyEndpointVerdict.LAYER_SCHEDULER_LOCAL;

            default:
                return ProxyEndpointVerdict.LAYER_LIFECYCLE_CANCELLED;
        }
    }

    private static String confidenceForPhase(String phase, PhaseInfo info) {
        String normalized = ProxyCheckDiagnostics.normalize(phase);
        if (info.kind == Kind.NEUTRAL) {
            return ProxyEndpointVerdict.CONFIDENCE_NONE;
        }
        switch (normalized) {
            case ProxyCheckDiagnostics.UNKNOWN_FAIL:
            case ProxyCheckDiagnostics.START_FAILED:
            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
                return ProxyEndpointVerdict.CONFIDENCE_LOW;
            case ProxyCheckDiagnostics.OK:
            case ProxyCheckDiagnostics.FIRST_TLS_APP_RECV:
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_RECV:
            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
                return ProxyEndpointVerdict.CONFIDENCE_HIGH;
            default:
                return info.kind == Kind.FAILURE ? ProxyEndpointVerdict.CONFIDENCE_MEDIUM : ProxyEndpointVerdict.CONFIDENCE_HIGH;
        }
    }

    private static String actionForPhase(String phase, PhaseInfo info) {
        if (info.kind == Kind.NEUTRAL) {
            return ProxyEndpointVerdict.ACTION_IGNORE;
        }
        if (info.usableSuccess) {
            return ProxyEndpointVerdict.ACTION_USABLE_SUCCESS;
        }
        if (info.canRotate || isOneShotTerminal(phase)) {
            return ProxyEndpointVerdict.ACTION_ROTATE;
        }
        if (info.canBackoff) {
            return ProxyEndpointVerdict.ACTION_BACKOFF;
        }
        return ProxyEndpointVerdict.ACTION_VISIBLE;
    }

    private static String userTextKeyForVerdict(String phase, String failureClass, PhaseInfo info) {
        if (info.kind == Kind.FAILURE
                || ProxyEndpointVerdict.FAILURE_CLASS_STALE_GENERATION_CANCELLED.equals(failureClass)
                || ProxyEndpointVerdict.FAILURE_CLASS_LIFECYCLE_CANCELLED.equals(failureClass)) {
            return userTextKeyForFailureClass(failureClass, phase);
        }
        return userTextKeyForPhase(phase);
    }

    static String userTextKeyForFailureClass(String failureClass, String phase) {
        if (ProxyEndpointVerdict.FAILURE_CLASS_DNS_FAILED.equals(failureClass)) {
            return "ProxyStatusHostResolveFailed";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_TCP_REFUSED.equals(failureClass)) {
            return "ProxyStatusTcpConnectionRefused";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_TCP_TIMEOUT.equals(failureClass)) {
            return "ProxyStatusTcpConnectTimeout";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_TCP_GATE_WAIT_TIMEOUT.equals(failureClass)) {
            return "ProxyStatusTcpConnectGateTimeout";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_TCP_FAILED.equals(failureClass)) {
            return "ProxyStatusTcpNotConnected";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_MTPROXY_NO_RESPONSE_AFTER_SEND.equals(failureClass)) {
            return "ProxyStatusMtproxyPacketSentNoResponse";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED.equals(failureClass)) {
            return "ProxyStatusDroppedAfterAppData";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_FAKETLS_NO_SERVER_HELLO.equals(failureClass)) {
            String normalized = ProxyCheckDiagnostics.normalize(phase);
            if (ProxyCheckDiagnostics.FAKETLS_SERVER_HELLO_WAIT_TIMEOUT.equals(normalized)
                    || ProxyCheckDiagnostics.SERVER_CLOSED_AFTER_CLIENT_HELLO.equals(normalized)) {
                return userTextKeyForPhase(phase);
            }
            return "ProxyStatusClientHelloNoServerHello";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_FAKETLS_BAD_SERVER_FLIGHT.equals(failureClass)) {
            return "ProxyStatusUnrecognizedTlsResponseAfterClientHello";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_SECRET_INVALID.equals(failureClass)) {
            return "ProxyStatusSecretInvalidDomain";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_PROBE_WAIT_TIMEOUT.equals(failureClass)) {
            return "ProxyStatusMtproxyProbeWaitTimeout";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_STALE_GENERATION_CANCELLED.equals(failureClass)
                || ProxyEndpointVerdict.FAILURE_CLASS_LIFECYCLE_CANCELLED.equals(failureClass)) {
            return "ProxyStatusBackgroundHandshakeAborted";
        }
        if (ProxyEndpointVerdict.FAILURE_CLASS_WAIT_TIMEOUT.equals(failureClass)) {
            return userTextKeyForPhase(phase);
        }
        return "ProxyStatusUnknownFail";
    }

    static String userTextKeyForPhase(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.OK:
                return "Available";
            case ProxyCheckDiagnostics.CHECKING:
                return "ProxyStatusCheckingConnection";
            case ProxyCheckDiagnostics.ADMISSION_QUEUE:
                return "ProxyStatusAdmissionQueue";
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN:
                return "ProxyStatusEndpointCooldown";
            case ProxyCheckDiagnostics.TCP_CONNECT_GATE:
                return "ProxyStatusTcpConnectGate";
            case ProxyCheckDiagnostics.DNS_COALESCE_WAIT:
                return "ProxyStatusDnsCoalesceWait";
            case ProxyCheckDiagnostics.DNS_CACHE_HIT:
                return "ProxyStatusDnsCacheHit";
            case ProxyCheckDiagnostics.DNS_CACHE_STORE:
                return "ProxyStatusDnsCacheStore";
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT:
                return "ProxyStatusMtproxyProbeWait";
            case ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT_TIMEOUT:
                return "ProxyStatusMtproxyProbeWaitTimeout";
            case ProxyCheckDiagnostics.PHASE_ADAPTIVE_RECIPE:
                return "ProxyStatusPhaseAdaptiveRecipe";
            case ProxyCheckDiagnostics.SECRET_DOMAIN_SANITIZED:
                return "ProxyStatusSecretDomainSanitized";
            case ProxyCheckDiagnostics.HOST_RESOLVE_START:
                return "ProxyStatusHostResolve";
            case ProxyCheckDiagnostics.CONNECT_START:
                return "ProxyStatusConnectStart";
            case ProxyCheckDiagnostics.SOCKET_CONNECT_START:
                return "ProxyStatusTcpConnecting";
            case ProxyCheckDiagnostics.SOCKET_CONNECTED:
                return "ProxyStatusTcpConnected";
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT:
                return "ProxyStatusClientHelloSent";
            case ProxyCheckDiagnostics.ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
                return "ProxyStatusAdmissionHoldAfterClientHelloFailure";
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_OK:
                return "ProxyStatusServerHelloOk";
            case ProxyCheckDiagnostics.ON_CONNECTED:
                return "ProxyStatusMtprotoStarting";
            case ProxyCheckDiagnostics.FIRST_TLS_APP_SENT:
                return "ProxyStatusFirstDataSent";
            case ProxyCheckDiagnostics.FIRST_TLS_APP_RECV:
                return "ProxyStatusFirstDataReceived";
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_SENT:
                return "ProxyStatusFirstMtproxyPacketSent";
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_RECV:
                return "ProxyStatusFirstMtproxyPacketReceived";
            case ProxyCheckDiagnostics.WAITING_TCP:
                return "ProxyStatusWaitingTcp";
            case ProxyCheckDiagnostics.START_FAILED:
                return "ProxyStatusStartFailed";
            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
                return "ProxyStatusConnectionNotStarted";
            case ProxyCheckDiagnostics.CONNECTING_TIMEOUT:
                return "ProxyStatusConnectingTimeout";
            case ProxyCheckDiagnostics.ADMISSION_TIMEOUT:
                return "ProxyStatusAdmissionTimeout";
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN_TIMEOUT:
                return "ProxyStatusEndpointCooldownTimeout";
            case ProxyCheckDiagnostics.DNS_COALESCE_TIMEOUT:
                return "ProxyStatusDnsCoalesceTimeout";
            case ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT:
                return "ProxyStatusDnsNegativeCacheHit";
            case ProxyCheckDiagnostics.DNS_BLOCKED_ZERO_ADDRESS:
                return "ProxyStatusDnsBlockedZeroAddress";
            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
                return "ProxyStatusHostResolveFailed";
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
                return "ProxyStatusHostResolveTimeout";
            case ProxyCheckDiagnostics.TCP_CONNECT_GATE_TIMEOUT:
                return "ProxyStatusTcpConnectGateTimeout";
            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
                return "ProxyStatusTcpNotConnected";
            case ProxyCheckDiagnostics.TCP_CONNECTION_REFUSED:
                return "ProxyStatusTcpConnectionRefused";
            case ProxyCheckDiagnostics.TCP_CONNECT_TIMEOUT:
                return "ProxyStatusTcpConnectTimeout";
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
                return "ProxyStatusTcpConnectedNoPong";
            case ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED:
                return "ProxyStatusNetworkBlockSuspected";
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR:
                return "ProxyStatusSecretInvalidDomainControlChar";
            case ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN:
                return "ProxyStatusSecretInvalidDomain";
            case ProxyCheckDiagnostics.TRUE_CLIENT_HELLO_TIMEOUT:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
                return "ProxyStatusClientHelloNoServerHello";
            case ProxyCheckDiagnostics.FAKETLS_SERVER_HELLO_WAIT_TIMEOUT:
                return "ProxyStatusFaketlsServerHelloWaitTimeout";
            case ProxyCheckDiagnostics.SERVER_CLOSED_AFTER_CLIENT_HELLO:
                return "ProxyStatusServerClosedAfterClientHello";
            case ProxyCheckDiagnostics.TLS_ALERT_AFTER_CLIENT_HELLO:
                return "ProxyStatusTlsAlertAfterClientHello";
            case ProxyCheckDiagnostics.SHORT_TLS_RESPONSE_AFTER_CLIENT_HELLO:
                return "ProxyStatusShortTlsResponseAfterClientHello";
            case ProxyCheckDiagnostics.UNRECOGNIZED_RESPONSE_AFTER_CLIENT_HELLO:
            case ProxyCheckDiagnostics.UNRECOGNIZED_TLS_RESPONSE_AFTER_CLIENT_HELLO:
                return "ProxyStatusUnrecognizedTlsResponseAfterClientHello";
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
                return "ProxyStatusServerHelloHmacMismatch";
            case ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED:
                return "ProxyStatusBackgroundHandshakeAborted";
            case ProxyCheckDiagnostics.HANDSHAKE_PROFILES_EXHAUSTED:
                return "ProxyStatusHandshakeProfilesExhausted";
            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
                return "ProxyStatusMtproxyPacketSentNoResponse";
            case ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA:
                return "ProxyStatusPostHandshakeNoAppData";
            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
                return "ProxyStatusDroppedEarlyAfterAppData";
            case ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA:
                return "ProxyStatusDroppedAfterAppData";
            case ProxyCheckDiagnostics.CANCELLED:
                return "ProxyStatusCancelled";
            case ProxyCheckDiagnostics.UNKNOWN_FAIL:
            default:
                return "ProxyStatusUnknownFail";
        }
    }

    private static PhaseInfo live(KeyScope keyScope) {
        return new PhaseInfo(Kind.LIVE, keyScope, false, false, true, false, false);
    }

    private static PhaseInfo success(KeyScope keyScope) {
        return new PhaseInfo(Kind.SUCCESS, keyScope, false, false, true, true, false);
    }

    private static PhaseInfo failure(KeyScope keyScope, boolean canBackoff, boolean canRotate) {
        return new PhaseInfo(Kind.FAILURE, keyScope, canBackoff, canRotate, true, false, false);
    }

    private static PhaseInfo terminalExactFailure() {
        return new PhaseInfo(Kind.FAILURE, KeyScope.EXACT, true, false, true, false, true);
    }

    private static final class PhaseInfo {
        final Kind kind;
        final KeyScope keyScope;
        final boolean canBackoff;
        final boolean canRotate;
        final boolean canOverwriteVisible;
        final boolean usableSuccess;
        final boolean terminalExactConfig;

        PhaseInfo(Kind kind, KeyScope keyScope, boolean canBackoff, boolean canRotate, boolean canOverwriteVisible, boolean usableSuccess, boolean terminalExactConfig) {
            this.kind = kind;
            this.keyScope = keyScope;
            this.canBackoff = canBackoff;
            this.canRotate = canRotate;
            this.canOverwriteVisible = canOverwriteVisible;
            this.usableSuccess = usableSuccess;
            this.terminalExactConfig = terminalExactConfig;
        }
    }
}
