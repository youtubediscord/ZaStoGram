package org.telegram.messenger;

import android.os.SystemClock;

public final class ProxyConnectionEvent {

    public static final String SOURCE_NATIVE_STAGE = "native_stage";
    public static final String SOURCE_PROXY_CHECK = "proxy_check";
    public static final String SOURCE_CONNECTED = "connected";
    public static final String SOURCE_CONNECT_START = "connect_start";

    public enum Origin {
        ACTIVE_SOCKET("active_socket"),
        PROXY_CHECK("proxy_check"),
        PROXY_LIST_ROW("proxy_list_row"),
        BACKGROUND_PRECHECK("background_precheck"),
        BACKGROUND_KEEPALIVE("background_keepalive"),
        SETTINGS_CHANGE("settings_change"),
        USER_SELECT("user_select"),
        STARTUP_RESTORE("startup_restore"),
        ROTATION_CANDIDATE("rotation_candidate");

        public final String wireName;

        Origin(String wireName) {
            this.wireName = wireName;
        }

        public static Origin fromNative(String origin) {
            if (origin == null) {
                return ACTIVE_SOCKET;
            }
            switch (origin) {
                case "active_socket":
                case "active_proxy":
                    return ACTIVE_SOCKET;
                case "proxy_check":
                    return PROXY_CHECK;
                case "proxy_list_row":
                    return PROXY_LIST_ROW;
                case "background_precheck":
                    return BACKGROUND_PRECHECK;
                case "background_keepalive":
                    return BACKGROUND_KEEPALIVE;
                case "settings_change":
                    return SETTINGS_CHANGE;
                case "user_select":
                    return USER_SELECT;
                case "startup_restore":
                    return STARTUP_RESTORE;
                case "rotation_candidate":
                    return ROTATION_CANDIDATE;
                default:
                    return ACTIVE_SOCKET;
            }
        }
    }

    public final String source;
    public final Origin origin;
    public final int account;
    public final String phase;
    public final String endpointKey;
    public final String networkKey;
    public final String probeKey;
    public final int activationGeneration;
    public final long timestamp;

    private ProxyConnectionEvent(String source, Origin origin, int account, String phase, String endpointKey, String networkKey, String probeKey, int activationGeneration, long timestamp) {
        this.source = source;
        this.origin = origin == null ? Origin.ACTIVE_SOCKET : origin;
        this.account = account;
        this.phase = ProxyCheckDiagnostics.normalize(phase);
        this.endpointKey = endpointKey == null ? "" : endpointKey;
        this.networkKey = networkKey == null || networkKey.length() == 0 ? ProxyEndpointKey.networkFromLiveStage(this.endpointKey) : networkKey;
        this.probeKey = probeKey == null ? "" : probeKey;
        this.activationGeneration = activationGeneration;
        this.timestamp = timestamp == 0 ? SystemClock.elapsedRealtime() : timestamp;
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey) {
        return nativeStage(account, phase, endpointKey, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, long timestamp) {
        return new ProxyConnectionEvent(SOURCE_NATIVE_STAGE, Origin.ACTIVE_SOCKET, account, phase, endpointKey, "", "", 0, timestamp);
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String origin) {
        return nativeStage(account, phase, endpointKey, "", origin, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String origin, long timestamp) {
        return nativeStage(account, phase, endpointKey, "", origin, timestamp);
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin) {
        return nativeStage(account, phase, endpointKey, probeKey, origin, 0, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin, long timestamp) {
        return nativeStage(account, phase, endpointKey, probeKey, origin, 0, timestamp);
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin, int activationGeneration) {
        return nativeStage(account, phase, endpointKey, probeKey, origin, activationGeneration, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin, int activationGeneration, long timestamp) {
        return new ProxyConnectionEvent(SOURCE_NATIVE_STAGE, Origin.fromNative(origin), account, phase, endpointKey, "", probeKey, activationGeneration, timestamp);
    }

    public static ProxyConnectionEvent proxyCheck(int account, SharedConfig.ProxyInfo proxyInfo, String phase) {
        return new ProxyConnectionEvent(SOURCE_PROXY_CHECK, Origin.PROXY_CHECK, account, phase, ProxyEndpointKey.liveStage(proxyInfo), ProxyEndpointKey.networkLiveStage(proxyInfo), "", 0, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent connected(int account, SharedConfig.ProxyInfo proxyInfo) {
        return new ProxyConnectionEvent(SOURCE_CONNECTED, Origin.ACTIVE_SOCKET, account, ProxyCheckDiagnostics.OK, ProxyEndpointKey.liveStage(proxyInfo), ProxyEndpointKey.networkLiveStage(proxyInfo), "", 0, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent connectStart(int account, SharedConfig.ProxyInfo proxyInfo) {
        return new ProxyConnectionEvent(SOURCE_CONNECT_START, Origin.ACTIVE_SOCKET, account, ProxyCheckDiagnostics.CONNECT_START, ProxyEndpointKey.liveStage(proxyInfo), ProxyEndpointKey.networkLiveStage(proxyInfo), "", 0, SystemClock.elapsedRealtime());
    }

    public static boolean isActiveProxyOrigin(Origin origin) {
        if (origin == null) {
            return true;
        }
        switch (origin) {
            case ACTIVE_SOCKET:
            case SETTINGS_CHANGE:
            case USER_SELECT:
            case STARTUP_RESTORE:
            case BACKGROUND_KEEPALIVE:
            case ROTATION_CANDIDATE:
                return true;
            default:
                return false;
        }
    }
}
