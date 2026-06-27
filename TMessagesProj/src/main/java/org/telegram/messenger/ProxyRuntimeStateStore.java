package org.telegram.messenger;

import android.os.SystemClock;

import org.telegram.tgnet.ConnectionsManager;

public final class ProxyRuntimeStateStore {

    private static final int MEDIA_STARTUP_PRE_USABLE_OPERATION_LIMIT = 1;
    private static final int MEDIA_STARTUP_PRE_USABLE_REQUEST_LIMIT = 1;
    private static final int MEDIA_STARTUP_RAMP_STEP_MS = 400;
    private static final int MEDIA_STARTUP_RAMP_INITIAL_LIMIT = 2;
    private static final int MEDIA_STARTUP_RAMP_INCREMENT = 2;
    private static final int MEDIA_STARTUP_RAMP_MAX_MS = 1600;

    private ProxyRuntimeStateStore() {
    }

    public static Decision onNativeStage(ProxyConnectionEvent event) {
        if (event == null) {
            return Decision.ignored("ignored_empty_event", ProxyCheckDiagnostics.UNKNOWN_FAIL, "");
        }
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        boolean concretePhase = ProxyPhasePolicy.isLivePhase(event.phase)
                || (ProxyPhasePolicy.isFailure(event.phase) && !ProxyCheckDiagnostics.UNKNOWN_FAIL.equals(event.phase));
        boolean selectedAccountStage = event.account == UserConfig.selectedAccount;
        boolean stageTargetsCurrentProxy = currentProxy != null && concretePhase && ProxyEndpointKey.matchesLiveStage(currentProxy, event.endpointKey);
        if (!stageTargetsCurrentProxy) {
            if (selectedAccountStage && currentProxy != null && concretePhase) {
                logControl("decision=ignored_stale_endpoint source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " current=" + ProxyEndpointKey.liveStage(currentProxy));
            }
            return Decision.ignored("ignored_stale_endpoint", event.phase, event.endpointKey);
        }
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(event.phase)) {
            markConnectionUsable(currentProxy, event.phase, event.timestamp);
            logControl("decision=visible_usable_success source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new Decision("visible_usable_success", event.phase, event.endpointKey, false, true, false);
        }
        if (shouldHoldLivePhaseByUsableSuccess(currentProxy, event)) {
            String heldBy = ProxyStatusMirror.diagnostic(currentProxy);
            logControl("decision=held_live_by_usable_success source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new Decision("held_live_by_usable_success", event.phase, event.endpointKey, false, false, true);
        }
        boolean freshUsableSuccess = ProxyHealthStore.hasFreshUsableSuccess(currentProxy, event.timestamp);
        if (!freshUsableSuccess
                && isCurrentProxyUsable(currentProxy, event.timestamp)
                && ProxyPhasePolicy.isLivePhase(event.phase)
                && !ProxyPhasePolicy.isProxyUsableSuccessPhase(event.phase)) {
            String heldBy = ProxyStatusMirror.diagnostic(currentProxy);
            logControl("decision=held_live_by_current_proxy_usable source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new Decision("held_live_by_current_proxy_usable", event.phase, event.endpointKey, false, false, true);
        }
        if (ProxyPhasePolicy.canBackoff(event.phase) && freshUsableSuccess) {
            String heldBy = ProxyStatusMirror.diagnostic(currentProxy);
            logControl("decision=held_by_usable_success source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new Decision("held_by_usable_success", event.phase, event.endpointKey, false, false, true);
        }
        if (ProxyPhasePolicy.canBackoff(event.phase) && isCurrentProxyUsable(currentProxy, event.timestamp)) {
            String heldBy = ProxyStatusMirror.diagnostic(currentProxy);
            logControl("decision=held_by_current_proxy_usable source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new Decision("held_by_current_proxy_usable", event.phase, event.endpointKey, false, false, true);
        }

        boolean visibleChanged = false;
        if (selectedAccountStage && ProxyPhasePolicy.canOverwriteVisible(event.phase)) {
            if (ProxyCheckDiagnostics.shouldKeepFreshFailure(currentProxy, event.phase)) {
                logControl("decision=held_by_fresh_failure source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + ProxyStatusMirror.diagnostic(currentProxy));
            } else {
                ProxyStatusMirror.mirrorVisiblePhase(currentProxy, event.phase, event.timestamp);
                visibleChanged = true;
            }
        }

        if (!ProxyPhasePolicy.canBackoff(event.phase)) {
            logControl("decision=visible_only source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new Decision("visible_only", event.phase, event.endpointKey, false, visibleChanged, false);
        }

        ProxyHealthStore.EndpointFailureResult failure = ProxyHealthStore.rememberLiveFailure(currentProxy, event.phase, event.timestamp);
        if (ProxyPhasePolicy.canRotate(event.phase) && failure.rotationAllowed) {
            logControl("decision=rotation_trigger source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new Decision("rotation_trigger", event.phase, event.endpointKey, true, visibleChanged, false);
        }
        if (ProxyPhasePolicy.canRotate(event.phase)) {
            logControl("decision=held_by_failure_hysteresis source=" + event.source + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " failures=" + failure.rotationFailures);
        }
        return new Decision("backoff", event.phase, event.endpointKey, false, visibleChanged, false);
    }

    private static boolean shouldHoldLivePhaseByUsableSuccess(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event) {
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
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(phase)) {
            return false;
        }
        return true;
    }

    public static boolean isFresh(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyStatusMirror.isFresh(proxyInfo);
    }

    public static boolean isEndpointBackedOff(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyHealthStore.isEndpointBackedOff(proxyInfo);
    }

    public static long nextAllowedCheckTime(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyHealthStore.nextAllowedCheckTime(proxyInfo);
    }

    public static boolean hasFreshUsableSuccess(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, SystemClock.elapsedRealtime());
    }

    public static boolean isCurrentProxyUsable(SharedConfig.ProxyInfo proxyInfo) {
        return isCurrentProxyUsable(proxyInfo, SystemClock.elapsedRealtime());
    }

    private static boolean isCurrentProxyUsable(SharedConfig.ProxyInfo proxyInfo, long now) {
        return ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)
                || isConnectedCurrentProxy(UserConfig.selectedAccount, proxyInfo);
    }

    public static long usableSuccessRemainingMs(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyHealthStore.usableSuccessRemainingMs(proxyInfo, SystemClock.elapsedRealtime());
    }

    public static boolean isMtProxyStartupFanoutLimited(int account) {
        if (!isMtProxyEnabledForStartupFanout()) {
            return false;
        }
        long age = ProxyHealthStore.lastUsableSuccessAgeMs(SharedConfig.currentProxy, SystemClock.elapsedRealtime());
        return age < 0 || age < MEDIA_STARTUP_RAMP_MAX_MS;
    }

    public static int fileLoaderStartupOperationLimit(int account, int normalLimit) {
        return fileLoaderStartupFanoutLimit(account, normalLimit, MEDIA_STARTUP_PRE_USABLE_OPERATION_LIMIT);
    }

    public static int fileLoaderStartupRequestLimit(int account, int normalLimit, boolean delayedPreload) {
        if (delayedPreload && isMtProxyEnabledForStartupFanout()
                && ProxyHealthStore.lastUsableSuccessAgeMs(SharedConfig.currentProxy, SystemClock.elapsedRealtime()) < 0) {
            return 0;
        }
        return fileLoaderStartupFanoutLimit(account, normalLimit, MEDIA_STARTUP_PRE_USABLE_REQUEST_LIMIT);
    }

    public static int fileLoaderStartupFanoutRecheckDelayMs(int account) {
        return isMtProxyStartupFanoutLimited(account) ? MEDIA_STARTUP_RAMP_STEP_MS : 0;
    }

    private static int fileLoaderStartupFanoutLimit(int account, int normalLimit, int preUsableLimit) {
        if (normalLimit <= 0 || !isMtProxyEnabledForStartupFanout()) {
            return normalLimit;
        }
        long age = ProxyHealthStore.lastUsableSuccessAgeMs(SharedConfig.currentProxy, SystemClock.elapsedRealtime());
        if (age < 0) {
            return Math.min(normalLimit, preUsableLimit);
        }
        if (age >= MEDIA_STARTUP_RAMP_MAX_MS) {
            return normalLimit;
        }
        int rampSteps = (int) (age / MEDIA_STARTUP_RAMP_STEP_MS);
        int rampLimit = MEDIA_STARTUP_RAMP_INITIAL_LIMIT + rampSteps * MEDIA_STARTUP_RAMP_INCREMENT;
        return Math.min(normalLimit, rampLimit);
    }

    private static boolean isMtProxyEnabledForStartupFanout() {
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        return SharedConfig.isProxyEnabled()
                && currentProxy != null
                && currentProxy.secret != null
                && currentProxy.secret.length() > 0
                && !currentProxy.isWssTransport();
    }

    public static String lastEndpointDiagnostic(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyHealthStore.lastEndpointDiagnostic(proxyInfo, ProxyStatusMirror.diagnostic(proxyInfo));
    }

    public static void markConnected(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        boolean changed = ProxyStatusMirror.isChecking(proxyInfo) || !ProxyStatusMirror.isAvailable(proxyInfo) || !ProxyStatusMirror.isFresh(proxyInfo);
        boolean preserveFreshProxyPhase = ProxyCheckDiagnostics.hasFreshFailure(proxyInfo) || ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now);
        if (!preserveFreshProxyPhase) {
            ProxyStatusMirror.markConnected(proxyInfo, now);
            ProxyHealthStore.rememberConnected(proxyInfo, now);
        }
        ProxyStatusMirror.clearTransientState(proxyInfo);
        if (changed) {
            logControl("decision=generic_connected endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " preserve=" + preserveFreshProxyPhase);
        }
    }

    public static void markConnectionStarting(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)) {
            logControl("decision=held_connect_start_by_usable_success source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return;
        }
        if (isCurrentProxyUsable(proxyInfo, now)) {
            logControl("decision=held_connect_start_by_current_proxy_usable source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return;
        }
        ProxyHealthStore.clearUsableSuccessHold(proxyInfo);
        ProxyStatusMirror.markConnectionStarting(proxyInfo, now);
        logControl("decision=visible_only source=" + ProxyConnectionEvent.SOURCE_CONNECT_START + " phase=" + ProxyCheckDiagnostics.CONNECT_START + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
    }

    public static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic) {
        markConnectionUsable(proxyInfo, diagnostic, SystemClock.elapsedRealtime());
    }

    public static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        if (proxyInfo == null) {
            return;
        }
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        ProxyStatusMirror.markConnectionUsable(proxyInfo, normalized, now);
        ProxyHealthStore.clearEndpointBackoff(proxyInfo, normalized, now);
        ProxyStatusMirror.clearTransientState(proxyInfo);
    }

    public static ProxyHealthStore.EndpointFailureResult markEndpointFailure(SharedConfig.ProxyInfo proxyInfo, String diagnostic) {
        if (proxyInfo == null || !ProxyPhasePolicy.canBackoff(diagnostic)) {
            return ProxyHealthStore.EndpointFailureResult.noop(diagnostic);
        }
        long now = SystemClock.elapsedRealtime();
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        if (ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)) {
            logControl("decision=held_by_usable_success source=live_failure phase=" + normalized + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return ProxyHealthStore.EndpointFailureResult.noop(normalized);
        }
        if (isCurrentProxyUsable(proxyInfo, now)) {
            logControl("decision=held_by_current_proxy_usable source=live_failure phase=" + normalized + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return ProxyHealthStore.EndpointFailureResult.noop(normalized);
        }
        ProxyHealthStore.EndpointFailureResult failure = ProxyHealthStore.rememberLiveFailure(proxyInfo, normalized, now);
        if (ProxyPhasePolicy.canRotate(normalized) && failure.rotationAllowed) {
            logControl("decision=rotation_trigger source=live_failure phase=" + normalized + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo));
        } else if (ProxyPhasePolicy.canRotate(normalized)) {
            logControl("decision=held_by_failure_hysteresis source=live_failure phase=" + normalized + " endpoint=" + ProxyEndpointKey.liveStage(proxyInfo) + " failures=" + failure.rotationFailures);
        }
        return failure;
    }

    public static void markEndpointCooldown(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (hasFreshConcreteProxyPhase(proxyInfo)) {
            return;
        }
        ProxyStatusMirror.markEndpointCooldown(proxyInfo, now);
    }

    public static void markCheckingIfNoFreshConcretePhase(SharedConfig.ProxyInfo proxyInfo) {
        ProxyStatusMirror.markCheckingIfNoFreshConcretePhase(proxyInfo);
    }

    public static void copyTransientState(SharedConfig.ProxyInfo target, SharedConfig.ProxyInfo source) {
        ProxyStatusMirror.copyTransientState(target, source);
    }

    public static void setChecking(SharedConfig.ProxyInfo proxyInfo, boolean checking) {
        ProxyStatusMirror.setChecking(proxyInfo, checking);
    }

    public static void setProxyCheckPingId(SharedConfig.ProxyInfo proxyInfo, long pingId) {
        ProxyStatusMirror.setProxyCheckPingId(proxyInfo, pingId);
    }

    public static void clearTransientState(SharedConfig.ProxyInfo proxyInfo) {
        ProxyStatusMirror.clearTransientState(proxyInfo);
    }

    public static void applyMeasuredProxyCheckResult(SharedConfig.ProxyInfo proxyInfo, long time, String diagnostic) {
        ProxyStatusMirror.applyMeasuredProxyCheckResult(proxyInfo, time, diagnostic);
    }

    public static String displayDiagnosticForProxyCheck(SharedConfig.ProxyInfo proxyInfo, long time, String normalizedDiagnostic) {
        if (time != -1 || !ProxyCheckDiagnostics.TCP_NOT_CONNECTED.equals(normalizedDiagnostic)) {
            return normalizedDiagnostic;
        }
        String previousDiagnostic = lastEndpointDiagnostic(proxyInfo);
        if (ProxyCheckDiagnostics.TCP_NOT_CONNECTED.equals(previousDiagnostic) || ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED.equals(previousDiagnostic)) {
            return ProxyCheckDiagnostics.NETWORK_BLOCK_SUSPECTED;
        }
        return normalizedDiagnostic;
    }

    public static long appliedTimeForProxyCheck(int account, SharedConfig.ProxyInfo proxyInfo, long time) {
        if (shouldPreserveProxyCheckFailure(account, proxyInfo, time)) {
            logControl("decision=proxy_check_shadowed endpoint=" + ProxyEndpointKey.endpoint(proxyInfo));
            return 0;
        }
        return time;
    }

    public static long callbackTimeForProxyCheck(int account, SharedConfig.ProxyInfo proxyInfo, long time) {
        if (shouldPreserveProxyCheckFailure(account, proxyInfo, time)) {
            return -1;
        }
        return time;
    }

    public static String appliedDiagnosticForProxyCheck(int account, SharedConfig.ProxyInfo proxyInfo, long time, String displayDiagnostic) {
        if (!shouldPreserveProxyCheckFailure(account, proxyInfo, time)) {
            return displayDiagnostic;
        }
        if (hasFreshConcreteProxyPhase(proxyInfo)) {
            return ProxyStatusMirror.diagnostic(proxyInfo);
        }
        return ProxyCheckDiagnostics.OK;
    }

    public static void rememberProxyCheckResult(int account, SharedConfig.ProxyInfo proxyInfo, long time, String displayDiagnostic) {
        String normalizedDiagnostic = ProxyCheckDiagnostics.normalize(displayDiagnostic);
        long now = SystemClock.elapsedRealtime();
        if (time != -1) {
            ProxyHealthStore.rememberConnected(proxyInfo, now);
            return;
        }
        if (shouldPreserveProxyCheckFailure(account, proxyInfo, time)) {
            logControl("decision=proxy_check_shadowed endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " phase=" + normalizedDiagnostic);
            return;
        }
        if (ProxyHealthStore.hasFreshUsableSuccess(proxyInfo, now)) {
            logControl("decision=held_by_usable_success source=" + ProxyConnectionEvent.SOURCE_PROXY_CHECK + " phase=" + normalizedDiagnostic + " endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " held_by=" + ProxyStatusMirror.diagnostic(proxyInfo));
            return;
        }
        ProxyHealthStore.rememberProxyCheckFailure(proxyInfo, normalizedDiagnostic, now);
    }

    public static boolean isSwitchableCandidate(SharedConfig.ProxyInfo info) {
        return info != null
                && info != SharedConfig.currentProxy
                && !ProxyStatusMirror.isChecking(info)
                && !ProxyCheckDiagnostics.hasFreshFailure(info)
                && !ProxyCheckDiagnostics.hasFreshEndpointCooldown(info)
                && !ProxyCheckDiagnostics.hasFreshUnresolvedLivePhase(info)
                && !isEndpointBackedOff(info);
    }

    public static boolean shouldScheduleFallback(int account, String diagnostic, String endpointKey) {
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        long now = SystemClock.elapsedRealtime();
        if (!ProxyPhasePolicy.isPunitiveFailure(normalized)) {
            logRotation("decision=ignored_non_punitive phase=" + normalized + " endpoint=" + endpointKey);
            return false;
        }
        boolean candidate = account == UserConfig.selectedAccount
                && currentProxy != null
                && ProxyEndpointKey.matchesLiveStage(currentProxy, endpointKey)
                && !isCurrentProxyUsable(currentProxy, now);
        if (currentProxy != null && ProxyEndpointKey.matchesLiveStage(currentProxy, endpointKey) && isCurrentProxyUsable(currentProxy, now)) {
            if (ProxyHealthStore.hasFreshUsableSuccess(currentProxy, now)) {
                logRotation("decision=held_by_usable_success phase=" + normalized + " endpoint=" + endpointKey + " held_by=" + ProxyStatusMirror.diagnostic(currentProxy));
            } else {
                logRotation("decision=held_by_current_proxy_usable phase=" + normalized + " endpoint=" + endpointKey + " held_by=" + ProxyStatusMirror.diagnostic(currentProxy));
            }
            return false;
        }
        ProxyHealthStore.EndpointFailureResult failure = candidate
                ? ProxyHealthStore.lastFailureResult(currentProxy, normalized, now)
                : ProxyHealthStore.EndpointFailureResult.noop(normalized);
        boolean result = candidate && failure.rotationAllowed;
        if (result) {
            logRotation("decision=trigger phase=" + normalized + " endpoint=" + endpointKey + " count=" + failure.rotationFailures + " required=" + ProxyHealthStore.punitiveFailuresToRotate());
        } else if (candidate) {
            logRotation("decision=waiting_hysteresis phase=" + normalized + " endpoint=" + endpointKey + " count=" + failure.rotationFailures + " required=" + ProxyHealthStore.punitiveFailuresToRotate());
            logControl("decision=held_by_failure_hysteresis phase=" + normalized + " endpoint=" + endpointKey + " failures=" + failure.rotationFailures);
        } else {
            logRotation("decision=fallback_not_scheduled phase=" + normalized + " endpoint=" + endpointKey);
            logControl("decision=fallback_not_scheduled phase=" + normalized + " endpoint=" + endpointKey + " failures=" + failure.rotationFailures);
        }
        return result;
    }

    public static boolean hasFreshConcreteProxyPhase(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyStatusMirror.hasFreshConcreteProxyPhase(proxyInfo);
    }

    private static boolean shouldPreserveProxyCheckFailure(int account, SharedConfig.ProxyInfo proxyInfo, long time) {
        if (time != -1 || proxyInfo == null || !targetsCurrentProxyEndpoint(proxyInfo)) {
            return false;
        }
        return isConnectedCurrentProxy(account, proxyInfo) || hasFreshConcreteProxyPhase(proxyInfo);
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

    private static void logControl(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_control " + message);
        }
    }

    private static void logRotation(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_rotation " + message);
        }
    }

    public static final class Decision {
        public final String decision;
        public final String phase;
        public final String endpointKey;
        public final boolean rotationTrigger;
        public final boolean visibleChanged;
        public final boolean shadowed;

        private Decision(String decision, String phase, String endpointKey, boolean rotationTrigger, boolean visibleChanged, boolean shadowed) {
            this.decision = decision;
            this.phase = phase;
            this.endpointKey = endpointKey;
            this.rotationTrigger = rotationTrigger;
            this.visibleChanged = visibleChanged;
            this.shadowed = shadowed;
        }

        private static Decision ignored(String decision, String phase, String endpointKey) {
            return new Decision(decision, phase, endpointKey, false, false, false);
        }
    }

}
