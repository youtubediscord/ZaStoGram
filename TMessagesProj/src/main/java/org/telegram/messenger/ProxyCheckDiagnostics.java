package org.telegram.messenger;

import android.text.TextUtils;

import org.telegram.tgnet.ConnectionsManager;
import org.telegram.ui.ActionBar.Theme;

public class ProxyCheckDiagnostics {

    private static final long LIVE_PHASE_STALE_MS = 45 * 1000L;
    private static final long FAILURE_PHASE_STALE_MS = 2 * 60 * 1000L;
    private static final long FAILURE_HOLD_EARLY_RETRY_MS = 15 * 1000L;

    public static final String OK = "ok";
    public static final String CHECKING = "checking";
    public static final String ADMISSION_QUEUE = "admission_queue";
    public static final String ENDPOINT_COOLDOWN = "endpoint_cooldown";
    public static final String TCP_CONNECT_GATE = "tcp_connect_gate";
    public static final String DNS_COALESCE_WAIT = "dns_coalesce_wait";
    public static final String DNS_CACHE_HIT = "dns_cache_hit";
    public static final String DNS_CACHE_STORE = "dns_cache_store";
    public static final String PHASE_ADAPTIVE_RECIPE = "phase_adaptive_recipe";
    public static final String HOST_RESOLVE_START = "host_resolve_start";
    public static final String CONNECT_START = "connect_start";
    public static final String SOCKET_CONNECT_START = "socket_connect_start";
    public static final String SOCKET_CONNECTED = "socket_connected";
    public static final String CLIENT_HELLO_SENT = "client_hello_sent";
    public static final String ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE = "admission_hold_after_client_hello_failure";
    public static final String SERVER_HELLO_HMAC_OK = "server_hello_hmac_ok";
    public static final String ON_CONNECTED = "on_connected";
    public static final String FIRST_TLS_APP_SENT = "first_tls_app_sent";
    public static final String FIRST_TLS_APP_RECV = "first_tls_app_recv";
    public static final String FIRST_MTPROXY_PACKET_SENT = "first_mtproxy_packet_sent";
    public static final String FIRST_MTPROXY_PACKET_RECV = "first_mtproxy_packet_recv";
    public static final String WAITING_TCP = "waiting_tcp";
    public static final String START_FAILED = "start_failed";
    public static final String CONNECTION_NOT_STARTED = "connection_not_started";
    public static final String CONNECTING_TIMEOUT = "connecting_timeout";
    public static final String ADMISSION_TIMEOUT = "admission_timeout";
    public static final String ENDPOINT_COOLDOWN_TIMEOUT = "endpoint_cooldown_timeout";
    public static final String DNS_COALESCE_TIMEOUT = "dns_coalesce_timeout";
    public static final String HOST_RESOLVE_FAILED = "host_resolve_failed";
    public static final String HOST_RESOLVE_TIMEOUT = "host_resolve_timeout";
    public static final String TCP_CONNECT_GATE_TIMEOUT = "tcp_connect_gate_timeout";
    public static final String TCP_NOT_CONNECTED = "tcp_not_connected";
    public static final String TCP_CONNECTED_NO_PONG = "tcp_connected_no_pong";
    public static final String NETWORK_BLOCK_SUSPECTED = "network_block_suspected";
    public static final String CLIENT_HELLO_SENT_NO_SERVER_HELLO = "client_hello_sent_no_server_hello";
    public static final String SERVER_HELLO_HMAC_MISMATCH = "server_hello_hmac_mismatch";
    public static final String MTPROXY_PACKET_SENT_NO_RESPONSE = "mtproxy_packet_sent_no_response";
    public static final String POST_HANDSHAKE_NO_APPDATA = "post_handshake_no_appdata";
    public static final String DROPPED_EARLY_AFTER_APPDATA = "dropped_early_after_appdata";
    public static final String DROPPED_AFTER_APPDATA = "dropped_after_appdata";
    public static final String CANCELLED = "cancelled";
    public static final String UNKNOWN_FAIL = "unknown_fail";

    public static String normalize(String diagnostic) {
        if (TextUtils.isEmpty(diagnostic)) {
            return UNKNOWN_FAIL;
        }
        switch (diagnostic) {
            case OK:
            case CHECKING:
            case ADMISSION_QUEUE:
            case ENDPOINT_COOLDOWN:
            case TCP_CONNECT_GATE:
            case DNS_COALESCE_WAIT:
            case DNS_CACHE_HIT:
            case DNS_CACHE_STORE:
            case PHASE_ADAPTIVE_RECIPE:
            case HOST_RESOLVE_START:
            case CONNECT_START:
            case SOCKET_CONNECT_START:
            case SOCKET_CONNECTED:
            case CLIENT_HELLO_SENT:
            case ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
            case SERVER_HELLO_HMAC_OK:
            case ON_CONNECTED:
            case FIRST_TLS_APP_SENT:
            case FIRST_TLS_APP_RECV:
            case FIRST_MTPROXY_PACKET_SENT:
            case FIRST_MTPROXY_PACKET_RECV:
            case WAITING_TCP:
            case START_FAILED:
            case CONNECTION_NOT_STARTED:
            case CONNECTING_TIMEOUT:
            case ADMISSION_TIMEOUT:
            case ENDPOINT_COOLDOWN_TIMEOUT:
            case DNS_COALESCE_TIMEOUT:
            case HOST_RESOLVE_FAILED:
            case HOST_RESOLVE_TIMEOUT:
            case TCP_CONNECT_GATE_TIMEOUT:
            case TCP_NOT_CONNECTED:
            case TCP_CONNECTED_NO_PONG:
            case NETWORK_BLOCK_SUSPECTED:
            case CLIENT_HELLO_SENT_NO_SERVER_HELLO:
            case SERVER_HELLO_HMAC_MISMATCH:
            case MTPROXY_PACKET_SENT_NO_RESPONSE:
            case POST_HANDSHAKE_NO_APPDATA:
            case DROPPED_EARLY_AFTER_APPDATA:
            case DROPPED_AFTER_APPDATA:
            case CANCELLED:
            case UNKNOWN_FAIL:
                return diagnostic;
            default:
                return UNKNOWN_FAIL;
        }
    }

    public static boolean isFailure(String diagnostic) {
        return ProxyPhasePolicy.isFailure(diagnostic);
    }

    public static boolean isLivePhase(String diagnostic) {
        return ProxyPhasePolicy.isLivePhase(diagnostic);
    }

    public static boolean isEarlyRetryPhase(String diagnostic) {
        switch (normalize(diagnostic)) {
            case ADMISSION_QUEUE:
            case HOST_RESOLVE_START:
            case CONNECT_START:
            case SOCKET_CONNECT_START:
                return true;
            default:
                return false;
        }
    }

    public static boolean hasFreshLivePhase(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null
                && proxyInfo.lastCheckDiagnosticTime != 0
                && android.os.SystemClock.elapsedRealtime() - proxyInfo.lastCheckDiagnosticTime < LIVE_PHASE_STALE_MS
                && isLivePhase(proxyInfo.lastCheckDiagnostic);
    }

    public static boolean hasFreshUnresolvedLivePhase(SharedConfig.ProxyInfo proxyInfo) {
        return hasFreshLivePhase(proxyInfo) && !isProxyUsableSuccessPhase(proxyInfo.lastCheckDiagnostic);
    }

    public static boolean hasFreshEndpointCooldown(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null
                && proxyInfo.lastCheckDiagnosticTime != 0
                && android.os.SystemClock.elapsedRealtime() - proxyInfo.lastCheckDiagnosticTime < LIVE_PHASE_STALE_MS
                && ENDPOINT_COOLDOWN.equals(normalize(proxyInfo.lastCheckDiagnostic));
    }

    public static boolean hasFreshFailure(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null
                && proxyInfo.lastCheckDiagnosticTime != 0
                && android.os.SystemClock.elapsedRealtime() - proxyInfo.lastCheckDiagnosticTime < FAILURE_PHASE_STALE_MS
                && isFailure(proxyInfo.lastCheckDiagnostic);
    }

    public static boolean shouldAccelerateProxyRotation(String diagnostic) {
        return ProxyPhasePolicy.shouldAccelerateProxyRotation(diagnostic);
    }

    public static boolean shouldKeepFreshFailure(SharedConfig.ProxyInfo proxyInfo, String incomingDiagnostic) {
        return proxyInfo != null
                && proxyInfo.lastCheckDiagnosticTime != 0
                && android.os.SystemClock.elapsedRealtime() - proxyInfo.lastCheckDiagnosticTime < FAILURE_HOLD_EARLY_RETRY_MS
                && isFailure(proxyInfo.lastCheckDiagnostic)
                && isEarlyRetryPhase(incomingDiagnostic);
    }

    public static boolean isProxyUsableSuccessPhase(String diagnostic) {
        return ProxyPhasePolicy.isProxyUsableSuccessPhase(diagnostic);
    }

    public static class HeaderStatusTitle {
        public final String key;
        public final int resId;

        private HeaderStatusTitle(String key, int resId) {
            this.key = key;
            this.resId = resId;
        }
    }

    private static HeaderStatusTitle title(String key, int resId) {
        return new HeaderStatusTitle(key, resId);
    }

    public static HeaderStatusTitle headerStatusTitle(SharedConfig.ProxyInfo proxyInfo, boolean proxyEnabled, int currentConnectionState) {
        if (!proxyEnabled) {
            return title("ProxyWindowStatusDisabled", R.string.ProxyWindowStatusDisabled);
        }
        if (proxyInfo == null) {
            return title("ProxyWindowStatusNoProxy", R.string.ProxyWindowStatusNoProxy);
        }
        if (hasFreshFailure(proxyInfo)) {
            return diagnosticTitle(proxyInfo.lastCheckDiagnostic);
        }
        if (currentConnectionState == ConnectionsManager.ConnectionStateConnected || currentConnectionState == ConnectionsManager.ConnectionStateUpdating) {
            return title("ProxyWindowStatusReady", R.string.ProxyWindowStatusReady);
        }
        if (hasFreshLivePhase(proxyInfo)) {
            return diagnosticTitle(proxyInfo.lastCheckDiagnostic);
        }
        if (currentConnectionState == ConnectionsManager.ConnectionStateConnectingToProxy) {
            return title("ProxyStatusWaitingTcp", R.string.ProxyStatusWaitingTcp);
        }
        if (proxyInfo.checking) {
            return title("ProxyWindowStatusChecking", R.string.ProxyWindowStatusChecking);
        }
        return title("ProxyStatusConnectingSlow", R.string.ProxyStatusConnectingSlow);
    }

    public static String statusText(SharedConfig.ProxyInfo proxyInfo, boolean currentProxyEnabled, int currentConnectionState) {
        if (proxyInfo == null) {
            return LocaleController.getString(R.string.ProxyStatusUnknownFail);
        }
        if (currentProxyEnabled) {
            if (hasFreshFailure(proxyInfo)) {
                return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
            }
            if (hasFreshLivePhase(proxyInfo)) {
                return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
            }
            if (currentConnectionState == ConnectionsManager.ConnectionStateConnected || currentConnectionState == ConnectionsManager.ConnectionStateUpdating) {
                if (proxyInfo.ping != 0) {
                    return LocaleController.getString(R.string.Connected) + ", " + LocaleController.formatString("Ping", R.string.Ping, proxyInfo.ping);
                }
                return LocaleController.getString(R.string.Connected);
            }
            if (currentConnectionState == ConnectionsManager.ConnectionStateConnectingToProxy) {
                return LocaleController.getString(R.string.ProxyStatusWaitingTcp);
            }
            if (proxyInfo.checking) {
                return LocaleController.getString(R.string.ProxyStatusCheckingConnection);
            }
            return LocaleController.getString(R.string.ProxyStatusConnectingSlow);
        }
        if (proxyInfo.checking) {
            return LocaleController.getString(R.string.ProxyStatusCheckingConnection);
        }
        if (hasFreshFailure(proxyInfo)) {
            return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
        }
        if (hasFreshLivePhase(proxyInfo) || hasFreshEndpointCooldown(proxyInfo)) {
            return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
        }
        if (proxyInfo.available && ProxyCheckScheduler.isFresh(proxyInfo)) {
            if (proxyInfo.ping != 0) {
                return LocaleController.getString(R.string.Available) + ", " + LocaleController.formatString("Ping", R.string.Ping, proxyInfo.ping);
            }
            return LocaleController.getString(R.string.Available);
        }
        return LocaleController.getString(R.string.ProxyStatusUnchecked);
    }

    public static String headerStatusText(SharedConfig.ProxyInfo proxyInfo, boolean proxyEnabled, int currentConnectionState) {
        if (!proxyEnabled) {
            return LocaleController.getString(R.string.ProxyWindowStatusDisabled);
        }
        if (proxyInfo == null) {
            return LocaleController.getString(R.string.ProxyWindowStatusNoProxy);
        }
        if (hasFreshFailure(proxyInfo)) {
            return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
        }
        if (hasFreshLivePhase(proxyInfo)) {
            return shortDiagnosticText(proxyInfo.lastCheckDiagnostic);
        }
        if (currentConnectionState == ConnectionsManager.ConnectionStateConnected || currentConnectionState == ConnectionsManager.ConnectionStateUpdating) {
            if (proxyInfo.ping != 0) {
                return LocaleController.getString(R.string.ProxyWindowStatusReady) + ", " + LocaleController.formatString("Ping", R.string.Ping, proxyInfo.ping);
            }
            return LocaleController.getString(R.string.ProxyWindowStatusReady);
        }
        if (currentConnectionState == ConnectionsManager.ConnectionStateConnectingToProxy) {
            return LocaleController.getString(R.string.ProxyStatusWaitingTcp);
        }
        if (proxyInfo.checking) {
            return LocaleController.getString(R.string.ProxyWindowStatusChecking);
        }
        return LocaleController.getString(R.string.ProxyStatusConnectingSlow);
    }

    public static String shortDiagnosticText(String diagnostic) {
        return diagnosticText(diagnostic);
    }

    private static HeaderStatusTitle diagnosticTitle(String diagnostic) {
        switch (normalize(diagnostic)) {
            case OK:
                return title("Available", R.string.Available);
            case CHECKING:
                return title("ProxyStatusCheckingConnection", R.string.ProxyStatusCheckingConnection);
            case ADMISSION_QUEUE:
                return title("ProxyStatusAdmissionQueue", R.string.ProxyStatusAdmissionQueue);
            case ENDPOINT_COOLDOWN:
                return title("ProxyStatusEndpointCooldown", R.string.ProxyStatusEndpointCooldown);
            case TCP_CONNECT_GATE:
                return title("ProxyStatusTcpConnectGate", R.string.ProxyStatusTcpConnectGate);
            case DNS_COALESCE_WAIT:
                return title("ProxyStatusDnsCoalesceWait", R.string.ProxyStatusDnsCoalesceWait);
            case DNS_CACHE_HIT:
                return title("ProxyStatusDnsCacheHit", R.string.ProxyStatusDnsCacheHit);
            case DNS_CACHE_STORE:
                return title("ProxyStatusDnsCacheStore", R.string.ProxyStatusDnsCacheStore);
            case PHASE_ADAPTIVE_RECIPE:
                return title("ProxyStatusPhaseAdaptiveRecipe", R.string.ProxyStatusPhaseAdaptiveRecipe);
            case HOST_RESOLVE_START:
                return title("ProxyStatusHostResolve", R.string.ProxyStatusHostResolve);
            case CONNECT_START:
                return title("ProxyStatusConnectStart", R.string.ProxyStatusConnectStart);
            case SOCKET_CONNECT_START:
                return title("ProxyStatusTcpConnecting", R.string.ProxyStatusTcpConnecting);
            case SOCKET_CONNECTED:
                return title("ProxyStatusTcpConnected", R.string.ProxyStatusTcpConnected);
            case CLIENT_HELLO_SENT:
                return title("ProxyStatusClientHelloSent", R.string.ProxyStatusClientHelloSent);
            case ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
                return title("ProxyStatusAdmissionHoldAfterClientHelloFailure", R.string.ProxyStatusAdmissionHoldAfterClientHelloFailure);
            case SERVER_HELLO_HMAC_OK:
                return title("ProxyStatusServerHelloOk", R.string.ProxyStatusServerHelloOk);
            case ON_CONNECTED:
                return title("ProxyStatusMtprotoStarting", R.string.ProxyStatusMtprotoStarting);
            case FIRST_TLS_APP_SENT:
                return title("ProxyStatusFirstDataSent", R.string.ProxyStatusFirstDataSent);
            case FIRST_TLS_APP_RECV:
                return title("ProxyStatusFirstDataReceived", R.string.ProxyStatusFirstDataReceived);
            case FIRST_MTPROXY_PACKET_SENT:
                return title("ProxyStatusFirstMtproxyPacketSent", R.string.ProxyStatusFirstMtproxyPacketSent);
            case FIRST_MTPROXY_PACKET_RECV:
                return title("ProxyStatusFirstMtproxyPacketReceived", R.string.ProxyStatusFirstMtproxyPacketReceived);
            case WAITING_TCP:
                return title("ProxyStatusWaitingTcp", R.string.ProxyStatusWaitingTcp);
            case START_FAILED:
                return title("ProxyStatusStartFailed", R.string.ProxyStatusStartFailed);
            case CONNECTION_NOT_STARTED:
                return title("ProxyStatusConnectionNotStarted", R.string.ProxyStatusConnectionNotStarted);
            case CONNECTING_TIMEOUT:
                return title("ProxyStatusConnectingTimeout", R.string.ProxyStatusConnectingTimeout);
            case ADMISSION_TIMEOUT:
                return title("ProxyStatusAdmissionTimeout", R.string.ProxyStatusAdmissionTimeout);
            case ENDPOINT_COOLDOWN_TIMEOUT:
                return title("ProxyStatusEndpointCooldownTimeout", R.string.ProxyStatusEndpointCooldownTimeout);
            case DNS_COALESCE_TIMEOUT:
                return title("ProxyStatusDnsCoalesceTimeout", R.string.ProxyStatusDnsCoalesceTimeout);
            case HOST_RESOLVE_FAILED:
                return title("ProxyStatusHostResolveFailed", R.string.ProxyStatusHostResolveFailed);
            case HOST_RESOLVE_TIMEOUT:
                return title("ProxyStatusHostResolveTimeout", R.string.ProxyStatusHostResolveTimeout);
            case TCP_CONNECT_GATE_TIMEOUT:
                return title("ProxyStatusTcpConnectGateTimeout", R.string.ProxyStatusTcpConnectGateTimeout);
            case TCP_NOT_CONNECTED:
                return title("ProxyStatusTcpNotConnected", R.string.ProxyStatusTcpNotConnected);
            case TCP_CONNECTED_NO_PONG:
                return title("ProxyStatusTcpConnectedNoPong", R.string.ProxyStatusTcpConnectedNoPong);
            case NETWORK_BLOCK_SUSPECTED:
                return title("ProxyStatusNetworkBlockSuspected", R.string.ProxyStatusNetworkBlockSuspected);
            case CLIENT_HELLO_SENT_NO_SERVER_HELLO:
                return title("ProxyStatusClientHelloNoServerHello", R.string.ProxyStatusClientHelloNoServerHello);
            case SERVER_HELLO_HMAC_MISMATCH:
                return title("ProxyStatusServerHelloHmacMismatch", R.string.ProxyStatusServerHelloHmacMismatch);
            case MTPROXY_PACKET_SENT_NO_RESPONSE:
                return title("ProxyStatusMtproxyPacketSentNoResponse", R.string.ProxyStatusMtproxyPacketSentNoResponse);
            case POST_HANDSHAKE_NO_APPDATA:
                return title("ProxyStatusPostHandshakeNoAppData", R.string.ProxyStatusPostHandshakeNoAppData);
            case DROPPED_EARLY_AFTER_APPDATA:
                return title("ProxyStatusDroppedEarlyAfterAppData", R.string.ProxyStatusDroppedEarlyAfterAppData);
            case DROPPED_AFTER_APPDATA:
                return title("ProxyStatusDroppedAfterAppData", R.string.ProxyStatusDroppedAfterAppData);
            case CANCELLED:
                return title("ProxyStatusCancelled", R.string.ProxyStatusCancelled);
            case UNKNOWN_FAIL:
            default:
                return title("ProxyStatusUnknownFail", R.string.ProxyStatusUnknownFail);
        }
    }

    public static int statusColorKey(SharedConfig.ProxyInfo proxyInfo, boolean currentProxyEnabled, int currentConnectionState) {
        if (currentProxyEnabled) {
            if (hasFreshFailure(proxyInfo)) {
                return Theme.key_text_RedRegular;
            }
            if (hasFreshLivePhase(proxyInfo)) {
                return isProxyUsableSuccessPhase(proxyInfo.lastCheckDiagnostic) ? Theme.key_windowBackgroundWhiteBlueText6 : Theme.key_windowBackgroundWhiteGrayText2;
            }
            if (currentConnectionState == ConnectionsManager.ConnectionStateConnected || currentConnectionState == ConnectionsManager.ConnectionStateUpdating) {
                return Theme.key_windowBackgroundWhiteBlueText6;
            }
            return Theme.key_windowBackgroundWhiteGrayText2;
        }
        if (proxyInfo == null) {
            return Theme.key_text_RedRegular;
        }
        if (proxyInfo.checking) {
            return Theme.key_windowBackgroundWhiteGrayText2;
        }
        if (hasFreshFailure(proxyInfo)) {
            return Theme.key_text_RedRegular;
        }
        if (hasFreshLivePhase(proxyInfo) || hasFreshEndpointCooldown(proxyInfo)) {
            return isProxyUsableSuccessPhase(proxyInfo.lastCheckDiagnostic) ? Theme.key_windowBackgroundWhiteGreenText : Theme.key_windowBackgroundWhiteGrayText2;
        }
        if (proxyInfo.available && ProxyCheckScheduler.isFresh(proxyInfo)) {
            return Theme.key_windowBackgroundWhiteGreenText;
        }
        return Theme.key_windowBackgroundWhiteGrayText2;
    }

    public static String diagnosticText(String diagnostic) {
        switch (normalize(diagnostic)) {
            case OK:
                return LocaleController.getString(R.string.Available);
            case CHECKING:
                return LocaleController.getString(R.string.ProxyStatusCheckingConnection);
            case ADMISSION_QUEUE:
                return LocaleController.getString(R.string.ProxyStatusAdmissionQueue);
            case ENDPOINT_COOLDOWN:
                return LocaleController.getString(R.string.ProxyStatusEndpointCooldown);
            case TCP_CONNECT_GATE:
                return LocaleController.getString(R.string.ProxyStatusTcpConnectGate);
            case DNS_COALESCE_WAIT:
                return LocaleController.getString(R.string.ProxyStatusDnsCoalesceWait);
            case DNS_CACHE_HIT:
                return LocaleController.getString(R.string.ProxyStatusDnsCacheHit);
            case DNS_CACHE_STORE:
                return LocaleController.getString(R.string.ProxyStatusDnsCacheStore);
            case PHASE_ADAPTIVE_RECIPE:
                return LocaleController.getString(R.string.ProxyStatusPhaseAdaptiveRecipe);
            case HOST_RESOLVE_START:
                return LocaleController.getString(R.string.ProxyStatusHostResolve);
            case CONNECT_START:
                return LocaleController.getString(R.string.ProxyStatusConnectStart);
            case SOCKET_CONNECT_START:
                return LocaleController.getString(R.string.ProxyStatusTcpConnecting);
            case SOCKET_CONNECTED:
                return LocaleController.getString(R.string.ProxyStatusTcpConnected);
            case CLIENT_HELLO_SENT:
                return LocaleController.getString(R.string.ProxyStatusClientHelloSent);
            case ADMISSION_HOLD_AFTER_CLIENT_HELLO_FAILURE:
                return LocaleController.getString(R.string.ProxyStatusAdmissionHoldAfterClientHelloFailure);
            case SERVER_HELLO_HMAC_OK:
                return LocaleController.getString(R.string.ProxyStatusServerHelloOk);
            case ON_CONNECTED:
                return LocaleController.getString(R.string.ProxyStatusMtprotoStarting);
            case FIRST_TLS_APP_SENT:
                return LocaleController.getString(R.string.ProxyStatusFirstDataSent);
            case FIRST_TLS_APP_RECV:
                return LocaleController.getString(R.string.ProxyStatusFirstDataReceived);
            case FIRST_MTPROXY_PACKET_SENT:
                return LocaleController.getString(R.string.ProxyStatusFirstMtproxyPacketSent);
            case FIRST_MTPROXY_PACKET_RECV:
                return LocaleController.getString(R.string.ProxyStatusFirstMtproxyPacketReceived);
            case WAITING_TCP:
                return LocaleController.getString(R.string.ProxyStatusWaitingTcp);
            case START_FAILED:
                return LocaleController.getString(R.string.ProxyStatusStartFailed);
            case CONNECTION_NOT_STARTED:
                return LocaleController.getString(R.string.ProxyStatusConnectionNotStarted);
            case CONNECTING_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusConnectingTimeout);
            case ADMISSION_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusAdmissionTimeout);
            case ENDPOINT_COOLDOWN_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusEndpointCooldownTimeout);
            case DNS_COALESCE_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusDnsCoalesceTimeout);
            case HOST_RESOLVE_FAILED:
                return LocaleController.getString(R.string.ProxyStatusHostResolveFailed);
            case HOST_RESOLVE_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusHostResolveTimeout);
            case TCP_CONNECT_GATE_TIMEOUT:
                return LocaleController.getString(R.string.ProxyStatusTcpConnectGateTimeout);
            case TCP_NOT_CONNECTED:
                return LocaleController.getString(R.string.ProxyStatusTcpNotConnected);
            case TCP_CONNECTED_NO_PONG:
                return LocaleController.getString(R.string.ProxyStatusTcpConnectedNoPong);
            case NETWORK_BLOCK_SUSPECTED:
                return LocaleController.getString(R.string.ProxyStatusNetworkBlockSuspected);
            case CLIENT_HELLO_SENT_NO_SERVER_HELLO:
                return LocaleController.getString(R.string.ProxyStatusClientHelloNoServerHello);
            case SERVER_HELLO_HMAC_MISMATCH:
                return LocaleController.getString(R.string.ProxyStatusServerHelloHmacMismatch);
            case MTPROXY_PACKET_SENT_NO_RESPONSE:
                return LocaleController.getString(R.string.ProxyStatusMtproxyPacketSentNoResponse);
            case POST_HANDSHAKE_NO_APPDATA:
                return LocaleController.getString(R.string.ProxyStatusPostHandshakeNoAppData);
            case DROPPED_EARLY_AFTER_APPDATA:
                return LocaleController.getString(R.string.ProxyStatusDroppedEarlyAfterAppData);
            case DROPPED_AFTER_APPDATA:
                return LocaleController.getString(R.string.ProxyStatusDroppedAfterAppData);
            case CANCELLED:
                return LocaleController.getString(R.string.ProxyStatusCancelled);
            case UNKNOWN_FAIL:
            default:
                return LocaleController.getString(R.string.ProxyStatusUnknownFail);
        }
    }
}
