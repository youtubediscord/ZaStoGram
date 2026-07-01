package org.telegram.messenger;

public final class ProxyEndpointVerdict {
    public static final String LAYER_SCHEDULER_LOCAL = "scheduler_local";
    public static final String LAYER_DNS = "dns";
    public static final String LAYER_TCP = "tcp";
    public static final String LAYER_MTPROXY_PLAIN = "mtproxy_plain";
    public static final String LAYER_FAKETLS_HANDSHAKE = "faketls_handshake";
    public static final String LAYER_POST_HANDSHAKE_DATA = "post_handshake_data";
    public static final String LAYER_LIFECYCLE_CANCELLED = "lifecycle_cancelled";

    public static final String FAILURE_CLASS_NONE = "none";
    public static final String FAILURE_CLASS_LIVE = "live";
    public static final String FAILURE_CLASS_SUCCESS = "success";
    public static final String FAILURE_CLASS_WAIT_TIMEOUT = "scheduler_wait_timeout";
    public static final String FAILURE_CLASS_DNS_FAILED = "dns_failed";
    public static final String FAILURE_CLASS_TCP_FAILED = "tcp_failed";
    public static final String FAILURE_CLASS_TCP_REFUSED = "tcp_refused";
    public static final String FAILURE_CLASS_TCP_TIMEOUT = "tcp_timeout";
    public static final String FAILURE_CLASS_TCP_GATE_WAIT_TIMEOUT = "tcp_gate_wait_timeout";
    public static final String FAILURE_CLASS_MTPROXY_NO_RESPONSE_AFTER_SEND = "mtproxy_no_response_after_send";
    public static final String FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED = "post_success_data_path_degraded";
    public static final String FAILURE_CLASS_FAKETLS_NO_SERVER_HELLO = "faketls_no_server_hello";
    public static final String FAILURE_CLASS_FAKETLS_BAD_SERVER_FLIGHT = "faketls_bad_server_flight";
    public static final String FAILURE_CLASS_SECRET_INVALID = "secret_invalid";
    public static final String FAILURE_CLASS_PROBE_WAIT_TIMEOUT = "probe_wait_timeout";
    public static final String FAILURE_CLASS_STALE_GENERATION_CANCELLED = "stale_generation_cancelled";
    public static final String FAILURE_CLASS_LIFECYCLE_CANCELLED = "lifecycle_cancelled";
    public static final String FAILURE_CLASS_UNKNOWN_FAILURE = "unknown_failure";
    public static final String CONFIDENCE_NONE = "none";
    public static final String CONFIDENCE_LOW = "low";
    public static final String CONFIDENCE_MEDIUM = "medium";
    public static final String CONFIDENCE_HIGH = "high";
    public static final String ACTION_IGNORE = "ignore";
    public static final String ACTION_VISIBLE = "visible";
    public static final String ACTION_USABLE_SUCCESS = "usable_success";
    public static final String ACTION_BACKOFF = "backoff";
    public static final String ACTION_ROTATE = "rotate";

    public final String phase;
    public final String layer;
    public final String failureClass;
    public final String confidence;
    public final String action;
    public final long stickyUntilMs;
    public final String userTextKey;
    public final String endpointKey;
    public final String networkKey;
    public final int activationGeneration;
    public final ProxyConnectionEvent.Origin origin;
    public final ProxyPhasePolicy.Kind kind;
    public final ProxyPhasePolicy.KeyScope keyScope;
    public final boolean canBackoff;
    public final boolean canRotate;
    public final boolean canOverwriteVisible;
    public final boolean usableSuccess;
    public final boolean terminalExactConfig;

    ProxyEndpointVerdict(String phase, String layer, String failureClass, String confidence, String action, long stickyUntilMs, String userTextKey, String endpointKey, String networkKey, int activationGeneration, ProxyConnectionEvent.Origin origin, ProxyPhasePolicy.Kind kind, ProxyPhasePolicy.KeyScope keyScope, boolean canBackoff, boolean canRotate, boolean canOverwriteVisible, boolean usableSuccess, boolean terminalExactConfig) {
        this.phase = ProxyCheckDiagnostics.normalize(phase);
        this.layer = layer == null ? LAYER_SCHEDULER_LOCAL : layer;
        this.failureClass = failureClass == null ? FAILURE_CLASS_NONE : failureClass;
        this.confidence = confidence == null ? CONFIDENCE_NONE : confidence;
        this.action = action == null ? ACTION_IGNORE : action;
        this.stickyUntilMs = stickyUntilMs;
        this.userTextKey = userTextKey == null ? "ProxyStatusUnknownFail" : userTextKey;
        this.endpointKey = endpointKey == null ? "" : endpointKey;
        this.networkKey = networkKey == null ? "" : networkKey;
        this.activationGeneration = activationGeneration;
        this.origin = origin == null ? ProxyConnectionEvent.Origin.ACTIVE_SOCKET : origin;
        this.kind = kind == null ? ProxyPhasePolicy.Kind.NEUTRAL : kind;
        this.keyScope = keyScope == null ? ProxyPhasePolicy.KeyScope.NONE : keyScope;
        this.canBackoff = canBackoff;
        this.canRotate = canRotate;
        this.canOverwriteVisible = canOverwriteVisible;
        this.usableSuccess = usableSuccess;
        this.terminalExactConfig = terminalExactConfig;
    }

    ProxyEndpointVerdict withIdentity(String endpointKey, String networkKey, int activationGeneration, ProxyConnectionEvent.Origin origin) {
        return new ProxyEndpointVerdict(
                phase,
                layer,
                failureClass,
                confidence,
                action,
                stickyUntilMs,
                userTextKey,
                endpointKey,
                networkKey,
                activationGeneration,
                origin,
                kind,
                keyScope,
                canBackoff,
                canRotate,
                canOverwriteVisible,
                usableSuccess,
                terminalExactConfig);
    }

    ProxyEndpointVerdict withClassification(String layer, String failureClass, String userTextKey) {
        return new ProxyEndpointVerdict(
                phase,
                layer,
                failureClass,
                confidence,
                action,
                stickyUntilMs,
                userTextKey,
                endpointKey,
                networkKey,
                activationGeneration,
                origin,
                kind,
                keyScope,
                canBackoff,
                canRotate,
                canOverwriteVisible,
                usableSuccess,
                terminalExactConfig);
    }

    public String originName() {
        return origin == null ? ProxyConnectionEvent.Origin.ACTIVE_SOCKET.wireName : origin.wireName;
    }

    public boolean isLivePhase() {
        return kind == ProxyPhasePolicy.Kind.LIVE || kind == ProxyPhasePolicy.Kind.SUCCESS;
    }

    public boolean isFailure() {
        return kind == ProxyPhasePolicy.Kind.FAILURE;
    }
}
