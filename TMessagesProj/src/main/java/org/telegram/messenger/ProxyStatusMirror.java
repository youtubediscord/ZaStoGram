package org.telegram.messenger;

import android.os.SystemClock;

final class ProxyStatusMirror {
    private static final long PROXY_CHECK_STALE_MS = 2 * 60 * 1000L;

    private ProxyStatusMirror() {
    }

    static boolean isFresh(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null
                && proxyInfo.availableCheckTime != 0
                && SystemClock.elapsedRealtime() - proxyInfo.availableCheckTime < PROXY_CHECK_STALE_MS;
    }

    static boolean isChecking(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null && proxyInfo.checking;
    }

    static boolean isAvailable(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null && proxyInfo.available;
    }

    static String diagnostic(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return ProxyCheckDiagnostics.UNKNOWN_FAIL;
        }
        return ProxyCheckDiagnostics.normalize(proxyInfo.lastCheckDiagnostic);
    }

    static boolean hasFreshConcreteProxyPhase(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyCheckDiagnostics.hasFreshFailure(proxyInfo)
                || ProxyCheckDiagnostics.hasFreshLivePhase(proxyInfo)
                || ProxyCheckDiagnostics.hasFreshEndpointCooldown(proxyInfo);
    }

    static boolean hasFreshVisibleUsableSuccess(SharedConfig.ProxyInfo proxyInfo, long now, long holdMs) {
        return visibleUsableSuccessRemainingMs(proxyInfo, now, holdMs) > 0;
    }

    static long visibleUsableSuccessRemainingMs(SharedConfig.ProxyInfo proxyInfo, long now, long holdMs) {
        if (proxyInfo == null
                || proxyInfo.lastCheckDiagnosticTime == 0
                || !ProxyPhasePolicy.isProxyUsableSuccessPhase(proxyInfo.lastCheckDiagnostic)) {
            return 0;
        }
        long elapsed = Math.max(0, now - proxyInfo.lastCheckDiagnosticTime);
        if (elapsed >= holdMs) {
            return 0;
        }
        return holdMs - elapsed;
    }

    static void markConnected(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return;
        }
        proxyInfo.available = true;
        proxyInfo.lastCheckDiagnostic = ProxyCheckDiagnostics.OK;
        proxyInfo.lastCheckDiagnosticTime = now;
        proxyInfo.lastCheckActivationGeneration = 0;
    }

    static void markConnectionStarting(SharedConfig.ProxyInfo proxyInfo, long now) {
        mirrorVisiblePhase(proxyInfo, ProxyCheckDiagnostics.CONNECT_START, now);
    }

    static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        markConnectionUsable(proxyInfo, diagnostic, now, 0);
    }

    static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now, int activationGeneration) {
        if (proxyInfo == null) {
            return;
        }
        proxyInfo.available = true;
        proxyInfo.availableCheckTime = now;
        mirrorVisiblePhase(proxyInfo, diagnostic, now, activationGeneration);
    }

    static void markEndpointCooldown(SharedConfig.ProxyInfo proxyInfo, long now) {
        mirrorVisiblePhase(proxyInfo, ProxyCheckDiagnostics.ENDPOINT_COOLDOWN, now);
    }

    static void markCheckingIfNoFreshConcretePhase(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null || hasFreshConcreteProxyPhase(proxyInfo)) {
            return;
        }
        mirrorVisiblePhase(proxyInfo, ProxyCheckDiagnostics.CHECKING, SystemClock.elapsedRealtime());
    }

    static void copyTransientState(SharedConfig.ProxyInfo target, SharedConfig.ProxyInfo source) {
        if (target == null || source == null) {
            return;
        }
        setChecking(target, source.checking);
        setProxyCheckPingId(target, source.proxyCheckPingId);
    }

    static void setChecking(SharedConfig.ProxyInfo proxyInfo, boolean checking) {
        if (proxyInfo == null) {
            return;
        }
        proxyInfo.checking = checking;
        if (checking) {
            markCheckingIfNoFreshConcretePhase(proxyInfo);
        }
    }

    static void setProxyCheckPingId(SharedConfig.ProxyInfo proxyInfo, long pingId) {
        if (proxyInfo == null) {
            return;
        }
        proxyInfo.proxyCheckPingId = pingId;
    }

    static void clearTransientState(SharedConfig.ProxyInfo proxyInfo) {
        setChecking(proxyInfo, false);
        setProxyCheckPingId(proxyInfo, 0);
    }

    static void applyMeasuredProxyCheckResult(SharedConfig.ProxyInfo proxyInfo, long time, String diagnostic) {
        if (proxyInfo == null) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        proxyInfo.availableCheckTime = now;
        mirrorVisiblePhase(proxyInfo, diagnostic, now);
        clearTransientState(proxyInfo);
        if (time == -1) {
            proxyInfo.available = false;
            proxyInfo.ping = 0;
        } else {
            proxyInfo.ping = time;
            proxyInfo.available = true;
        }
    }

    static void mirrorVisiblePhase(SharedConfig.ProxyInfo proxyInfo, String phase, long now) {
        mirrorVisiblePhase(proxyInfo, phase, now, 0);
    }

    static void mirrorVisiblePhase(SharedConfig.ProxyInfo proxyInfo, String phase, long now, int activationGeneration) {
        if (proxyInfo == null) {
            return;
        }
        proxyInfo.lastCheckDiagnostic = ProxyCheckDiagnostics.normalize(phase);
        proxyInfo.lastCheckDiagnosticTime = now;
        proxyInfo.lastCheckActivationGeneration = activationGeneration;
    }
}
