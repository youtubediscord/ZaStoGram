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

    private static final PhaseInfo NEUTRAL_NONE = new PhaseInfo(Kind.NEUTRAL, KeyScope.NONE, false, false, true, false);

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
            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
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
                || !canRotate(phase);
    }

    public static boolean canOverwriteVisible(String phase) {
        return classify(phase).canOverwriteVisible;
    }

    public static boolean usableSuccess(String phase) {
        return classify(phase).usableSuccess;
    }

    public static boolean isLivePhase(String phase) {
        Kind kind = kind(phase);
        return kind == Kind.LIVE || kind == Kind.SUCCESS;
    }

    public static boolean isFailure(String phase) {
        return kind(phase) == Kind.FAILURE;
    }

    public static boolean shouldAccelerateProxyRotation(String phase) {
        return canRotate(phase);
    }

    public static boolean isProxyUsableSuccessPhase(String phase) {
        return usableSuccess(phase);
    }

    private static PhaseInfo classify(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.OK:
            case ProxyCheckDiagnostics.CHECKING:
            case ProxyCheckDiagnostics.CANCELLED:
                return NEUTRAL_NONE;

            case ProxyCheckDiagnostics.ADMISSION_QUEUE:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN:
            case ProxyCheckDiagnostics.PHASE_ADAPTIVE_RECIPE:
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
            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_SENT:
            case ProxyCheckDiagnostics.WAITING_TCP:
                return live(KeyScope.NETWORK);

            case ProxyCheckDiagnostics.FIRST_TLS_APP_RECV:
                return success(KeyScope.EXACT);

            case ProxyCheckDiagnostics.FIRST_MTPROXY_PACKET_RECV:
                return success(KeyScope.NETWORK);

            case ProxyCheckDiagnostics.CONNECTION_NOT_STARTED:
                return failure(KeyScope.NONE, false, false);

            case ProxyCheckDiagnostics.ADMISSION_TIMEOUT:
            case ProxyCheckDiagnostics.ENDPOINT_COOLDOWN_TIMEOUT:
                return failure(KeyScope.EXACT, false, false);

            case ProxyCheckDiagnostics.TCP_CONNECT_GATE_TIMEOUT:
            case ProxyCheckDiagnostics.DNS_COALESCE_TIMEOUT:
                return failure(KeyScope.NETWORK, false, false);

            case ProxyCheckDiagnostics.HOST_RESOLVE_FAILED:
            case ProxyCheckDiagnostics.HOST_RESOLVE_TIMEOUT:
            case ProxyCheckDiagnostics.TCP_NOT_CONNECTED:
            case ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG:
            case ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED:
            case ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE:
            case ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA:
                return failure(KeyScope.NETWORK, true, true);

            case ProxyCheckDiagnostics.CLIENT_HELLO_SENT_NO_SERVER_HELLO:
            case ProxyCheckDiagnostics.SERVER_HELLO_HMAC_MISMATCH:
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

    private static PhaseInfo live(KeyScope keyScope) {
        return new PhaseInfo(Kind.LIVE, keyScope, false, false, true, false);
    }

    private static PhaseInfo success(KeyScope keyScope) {
        return new PhaseInfo(Kind.SUCCESS, keyScope, false, false, true, true);
    }

    private static PhaseInfo failure(KeyScope keyScope, boolean canBackoff, boolean canRotate) {
        return new PhaseInfo(Kind.FAILURE, keyScope, canBackoff, canRotate, true, false);
    }

    private static final class PhaseInfo {
        final Kind kind;
        final KeyScope keyScope;
        final boolean canBackoff;
        final boolean canRotate;
        final boolean canOverwriteVisible;
        final boolean usableSuccess;

        PhaseInfo(Kind kind, KeyScope keyScope, boolean canBackoff, boolean canRotate, boolean canOverwriteVisible, boolean usableSuccess) {
            this.kind = kind;
            this.keyScope = keyScope;
            this.canBackoff = canBackoff;
            this.canRotate = canRotate;
            this.canOverwriteVisible = canOverwriteVisible;
            this.usableSuccess = usableSuccess;
        }
    }
}
