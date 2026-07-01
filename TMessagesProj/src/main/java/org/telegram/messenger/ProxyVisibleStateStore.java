package org.telegram.messenger;

import android.os.SystemClock;

import org.telegram.tgnet.ConnectionsManager;

final class ProxyVisibleStateStore {
    static final long DNS_VISIBLE_DELAY_MS = 800L;
    static final long PROBE_WAIT_VISIBLE_REPEAT_MS = 5 * 1000L;

    private static long pendingDnsVisibleGeneration;
    private static String pendingDnsVisibleEndpointKey = "";
    private static String pendingDnsVisiblePhase = "";
    private static int pendingDnsVisibleAccount = -1;
    private static long pendingDnsVisibleStartedAtMs;
    private static String lastVisibleProbeWaitEndpointKey = "";
    private static String lastVisibleProbeWaitProbeKey = "";
    private static int lastVisibleProbeWaitActivationGeneration;
    private static long lastVisibleProbeWaitAtMs;

    private ProxyVisibleStateStore() {
    }

    static boolean currentProxyHasFreshUsableSuccessOrConnected(SharedConfig.ProxyInfo proxyInfo, long now) {
        return proxyInfo != null
                && (ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now) || (!isMtProxy(proxyInfo) && isCurrentProxyUsable(proxyInfo, now)));
    }

    static boolean isCurrentProxyUsable(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (ProxyHealthStore.isEndpointRotatedAway(proxyInfo, now)) {
            return false;
        }
        if (isMtProxy(proxyInfo)) {
            return ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now);
        }
        return ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)
                || isConnectedCurrentProxy(UserConfig.selectedAccount, proxyInfo);
    }

    static boolean shouldHoldLivePhaseByUsableSuccess(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        if (proxyInfo == null || event == null) {
            return false;
        }
        String phase = ProxyCheckDiagnostics.normalize(event.phase);
        if (!ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, event.timestamp)) {
            return false;
        }
        if (!ProxyPhasePolicy.isLivePhase(phase)) {
            return false;
        }
        return !ProxyPhasePolicy.isProxyUsableSuccessPhase(phase);
    }

    static boolean shouldShadowFailureByUsableSuccess(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        if (proxyInfo == null || event == null) {
            return false;
        }
        return ProxyHealthStore.shouldShadowFailureByUsableSuccess(proxyInfo, event.phase, event.timestamp);
    }

    static String heldByUsablePhase(SharedConfig.ProxyInfo proxyInfo, long now) {
        String heldBy = ProxyHealthStore.lastUsablePhase(proxyInfo, now);
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(heldBy)) {
            return heldBy;
        }
        heldBy = ProxyStatusMirror.diagnostic(proxyInfo);
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(heldBy)) {
            return heldBy;
        }
        return ProxyCheckDiagnostics.FIRST_TLS_APP_RECV;
    }

    static String heldByCurrentProxyPhase(SharedConfig.ProxyInfo proxyInfo, long now) {
        String heldBy = ProxyHealthStore.lastUsablePhase(proxyInfo, now);
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(heldBy)) {
            return heldBy;
        }
        heldBy = ProxyStatusMirror.diagnostic(proxyInfo);
        if (ProxyPhasePolicy.isFailure(heldBy)) {
            return ProxyCheckDiagnostics.OK;
        }
        return heldBy;
    }

    static boolean shouldDelayDnsVisiblePhase(String phase) {
        switch (ProxyCheckDiagnostics.normalize(phase)) {
            case ProxyCheckDiagnostics.HOST_RESOLVE_START:
            case ProxyCheckDiagnostics.DNS_COALESCE_WAIT:
                return true;
            default:
                return false;
        }
    }

    static void scheduleDnsVisiblePhase(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        if (proxyInfo == null || event == null || event.endpointKey.length() == 0) {
            return;
        }
        long generation = ++pendingDnsVisibleGeneration;
        pendingDnsVisibleEndpointKey = event.endpointKey;
        pendingDnsVisiblePhase = event.phase;
        pendingDnsVisibleAccount = event.account;
        pendingDnsVisibleStartedAtMs = event.timestamp;
        AndroidUtilities.runOnUIThread(() -> promotePendingDnsVisiblePhase(generation), DNS_VISIBLE_DELAY_MS);
    }

    static void clearPendingDnsVisiblePhase(String endpointKey, long now) {
        if (pendingDnsVisibleEndpointKey.length() == 0 || !ProxyEndpointKey.sameTelemetryEndpointKey(pendingDnsVisibleEndpointKey, endpointKey)) {
            return;
        }
        pendingDnsVisibleGeneration++;
        pendingDnsVisibleEndpointKey = "";
        pendingDnsVisiblePhase = "";
        pendingDnsVisibleAccount = -1;
        pendingDnsVisibleStartedAtMs = 0;
    }

    static boolean mirrorVisiblePhaseIfAllowed(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        return mirrorVisiblePhaseIfAllowed(proxyInfo, event, event == null ? null : event.phase);
    }

    static boolean mirrorVisiblePhaseIfAllowed(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event, String visiblePhase) {
        if (proxyInfo == null || event == null) {
            return false;
        }
        if (shouldHoldVisiblePhaseByFreshFailure(proxyInfo, event)) {
            return false;
        }
        ProxyStatusMirror.mirrorVisiblePhase(proxyInfo, visiblePhase, event.timestamp, event.activationGeneration);
        return true;
    }

    static boolean shouldCoalesceProbeWait(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        if (proxyInfo == null || event == null || !ProxyCheckDiagnostics.MTPROXY_PROBE_WAIT.equals(ProxyCheckDiagnostics.normalize(event.phase))) {
            return false;
        }
        String endpointKey = event.endpointKey == null ? "" : event.endpointKey;
        if (endpointKey.length() == 0) {
            return false;
        }
        String probeKey = event.probeKey == null ? "" : event.probeKey;
        boolean sameProbe = ProxyEndpointKey.sameTelemetryEndpointKey(lastVisibleProbeWaitEndpointKey, endpointKey)
                && probeKey.equals(lastVisibleProbeWaitProbeKey)
                && event.activationGeneration == lastVisibleProbeWaitActivationGeneration;
        if (sameProbe && event.timestamp - lastVisibleProbeWaitAtMs < PROBE_WAIT_VISIBLE_REPEAT_MS) {
            return true;
        }
        lastVisibleProbeWaitEndpointKey = endpointKey;
        lastVisibleProbeWaitProbeKey = probeKey;
        lastVisibleProbeWaitActivationGeneration = event.activationGeneration;
        lastVisibleProbeWaitAtMs = event.timestamp;
        return false;
    }

    static void resetProbeWaitCoalescing() {
        lastVisibleProbeWaitEndpointKey = "";
        lastVisibleProbeWaitProbeKey = "";
        lastVisibleProbeWaitActivationGeneration = 0;
        lastVisibleProbeWaitAtMs = 0;
    }

    static boolean shouldHoldVisiblePhaseByFreshFailure(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
        if (proxyInfo == null || event == null) {
            return false;
        }
        if (!ProxyCheckDiagnostics.shouldKeepFreshFailure(proxyInfo, event.phase, event.activationGeneration)) {
            return false;
        }
        ProxyRuntimeStateStore.logControl("decision=held_by_fresh_failure source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
        return true;
    }

    static boolean markConnected(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return false;
        }
        clearPendingDnsVisiblePhase(ProxyEndpointKey.liveStage(proxyInfo), now);
        if (ProxyHealthStore.isEndpointRotatedAway(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=ignored_rotated_away source=" + ProxyConnectionEvent.SOURCE_CONNECTED + " phase=" + ProxyCheckDiagnostics.OK + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
            return false;
        }
        boolean changed = ProxyStatusMirror.isChecking(proxyInfo) || !ProxyStatusMirror.isAvailable(proxyInfo) || !ProxyStatusMirror.isFresh(proxyInfo);
        boolean preserveFreshProxyPhase = ProxyCheckDiagnostics.hasFreshFailure(proxyInfo) || ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now);
        if (isMtProxy(proxyInfo) && !ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + ProxyConnectionEvent.SOURCE_CONNECTED + " phase=" + ProxyCheckDiagnostics.OK + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " reason=mtproxy_wait_data_path");
            return false;
        }
        if (!preserveFreshProxyPhase) {
            ProxyStatusMirror.markConnected(proxyInfo, now);
        }
        ProxyStatusMirror.clearTransientState(proxyInfo);
        if (changed) {
            ProxyRuntimeStateStore.logControl("decision=generic_connected endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " preserve=" + preserveFreshProxyPhase);
        }
        return !preserveFreshProxyPhase;
    }

    static void markConnectionStarting(SharedConfig.ProxyInfo proxyInfo, long now, ProxyConnectionEvent.Origin origin) {
        if (proxyInfo == null) {
            return;
        }
        clearPendingDnsVisiblePhase(ProxyEndpointKey.liveStage(proxyInfo), now);
        boolean forceVisibleActivation = origin == ProxyConnectionEvent.Origin.USER_SELECT
                || origin == ProxyConnectionEvent.Origin.SETTINGS_CHANGE
                || origin == ProxyConnectionEvent.Origin.STARTUP_RESTORE;
        if (forceVisibleActivation) {
            resetProbeWaitCoalescing();
            ProxyHealthStore.clearUsableSuccessHold(proxyInfo, now, origin.wireName);
            ProxyStatusMirror.markConnectionStarting(proxyInfo, now);
            ProxyRuntimeStateStore.logControl("decision=visible_only source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " origin=" + origin.wireName + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
            return;
        }
        if (ProxyHealthStore.isEndpointRotatedAway(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=ignored_rotated_away source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
            return;
        }
        if (ProxyCheckDiagnostics.shouldKeepFreshFailure(proxyInfo, ProxyCheckDiagnostics.CONNECT_START)) {
            ProxyRuntimeStateStore.logControl("decision=held_by_fresh_failure source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " origin=" + origin.wireName + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return;
        }
        if (ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=held_live_by_usable_success source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + heldByUsablePhase(proxyInfo, now));
            return;
        }
        if (isCurrentProxyUsable(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=held_live_by_current_proxy_usable source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + heldByCurrentProxyPhase(proxyInfo, now));
            return;
        }
        ProxyStatusMirror.markConnectionStarting(proxyInfo, now);
        ProxyRuntimeStateStore.logControl("decision=visible_only source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " origin=" + origin.wireName + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
    }

    static boolean markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now, int activationGeneration) {
        if (proxyInfo == null) {
            return false;
        }
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        clearPendingDnsVisiblePhase(ProxyEndpointKey.liveStage(proxyInfo), now);
        if (ProxyHealthStore.isEndpointRotatedAway(proxyInfo, now)) {
            ProxyRuntimeStateStore.logControl("decision=ignored_rotated_away source=usable_success phase=" + normalized + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
            return false;
        }
        ProxyStatusMirror.markConnectionUsable(proxyInfo, normalized, now, activationGeneration);
        ProxyStatusMirror.clearTransientState(proxyInfo);
        return true;
    }

    private static void promotePendingDnsVisiblePhase(long generation) {
        if (generation != pendingDnsVisibleGeneration || pendingDnsVisibleEndpointKey.length() == 0) {
            return;
        }
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        String endpointKey = pendingDnsVisibleEndpointKey;
        String phase = pendingDnsVisiblePhase;
        int account = pendingDnsVisibleAccount;
        long startedAtMs = pendingDnsVisibleStartedAtMs;
        long now = SystemClock.elapsedRealtime();
        if (currentProxy == null
                || !ProxyEndpointKey.matchesTelemetryEndpointKey(currentProxy, endpointKey)
                || !shouldDelayDnsVisiblePhase(phase)
                || now - startedAtMs < DNS_VISIBLE_DELAY_MS
                || currentProxy.lastCheckDiagnosticTime > startedAtMs
                || ProxyHealthStore.hasFreshUsableSuccess(currentProxy, now)
                || isCurrentProxyUsable(currentProxy, now)
                || ProxyCheckDiagnostics.hasFreshFailure(currentProxy)) {
            clearPendingDnsVisiblePhase(endpointKey, now);
            return;
        }
        ProxyStatusMirror.mirrorVisiblePhase(currentProxy, phase, now);
        ProxyRuntimeStateStore.logControl("decision=visible_delayed_dns source=" + ProxyConnectionEvent.SOURCE_NATIVE_STAGE + " account=" + account + " phase=" + phase + " endpoint=" + endpointKey + " delay_ms=" + (now - startedAtMs));
        clearPendingDnsVisiblePhase(endpointKey, now);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyConnectionStageChanged, phase, endpointKey, ProxyConnectionEvent.Origin.ACTIVE_SOCKET.wireName);
        AccountInstance.getInstance(account).getNotificationCenter().postNotificationName(NotificationCenter.proxyConnectionStageChanged, phase, endpointKey, ProxyConnectionEvent.Origin.ACTIVE_SOCKET.wireName);
    }

    private static boolean isMtProxy(SharedConfig.ProxyInfo proxyInfo) {
        return proxyInfo != null && proxyInfo.secret != null && proxyInfo.secret.length() > 0;
    }

    private static boolean isConnectedCurrentProxy(int account, SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null || !targetsCurrentProxyEndpoint(proxyInfo)) {
            return false;
        }
        int state = ConnectionsManager.getInstance(account).getConnectionState();
        return state == ConnectionsManager.ConnectionStateConnected || state == ConnectionsManager.ConnectionStateUpdating;
    }

    private static boolean targetsCurrentProxyEndpoint(SharedConfig.ProxyInfo proxyInfo) {
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        String key = ProxyEndpointKey.exact(proxyInfo);
        return currentProxy != null && key != null && key.equals(ProxyEndpointKey.exact(currentProxy));
    }
}
