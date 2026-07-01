package org.telegram.messenger;

import android.os.SystemClock;

import java.util.HashMap;

final class ProxyHealthStore {
    private static final long PROXY_CHECK_FAILURE_BACKOFF_MS = 2 * 60 * 1000L;
    private static final long PROXY_CHECK_FAILURE_BACKOFF_MAX_MS = 8 * 60 * 1000L;
    private static final long PROXY_CHECK_LIVE_FAILURE_DEDUP_MS = 1500L;
    private static final long PROXY_CHECK_CONNECTED_GRACE_MS = 60 * 1000L;
    private static final long INVALID_SECRET_FAILURE_BACKOFF_MS = 15 * 60 * 1000L;
    private static final long INVALID_SECRET_ROTATED_AWAY_HOLD_MS = 15 * 60 * 1000L;
    private static final long USABLE_SUCCESS_HOLD_MS = 45 * 1000L;
    private static final long ROTATED_AWAY_HOLD_MS = 45 * 1000L;
    private static final long PUNITIVE_FAILURE_WINDOW_MS = 30 * 1000L;
    private static final int PUNITIVE_FAILURES_TO_ROTATE = 2;
    private static final int POST_SUCCESS_DATA_PATH_SHADOWS = 1;

    private static final HashMap<String, EndpointState> endpointStates = new HashMap<>();
    private static final HashMap<String, Long> endpointTelemetryIgnoreUntil = new HashMap<>();

    enum EndpointLifecycle {
        TESTING,
        USABLE,
        DEGRADED,
        QUARANTINED,
        ROTATED_AWAY
    }

    private ProxyHealthStore() {
    }

    static boolean isEndpointBackedOff(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return false;
        }
        EndpointState state = endpointFailureState(proxyInfo);
        return state != null
                && state.consecutiveFailures > 0
                && nextAllowedCheckTime(proxyInfo) > SystemClock.elapsedRealtime();
    }

    static long nextAllowedCheckTime(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return 0;
        }
        EndpointState exactState = endpointStates.get(ProxyEndpointKey.exact(proxyInfo));
        EndpointState networkState = endpointStates.get(ProxyEndpointKey.network(proxyInfo));
        long exactTime = exactState == null ? 0 : exactState.nextCheckTime;
        long networkTime = networkState == null ? 0 : networkState.nextCheckTime;
        return Math.max(exactTime, networkTime);
    }

    static String lastEndpointDiagnostic(SharedConfig.ProxyInfo proxyInfo, String fallbackDiagnostic) {
        if (proxyInfo == null) {
            return ProxyCheckDiagnostics.UNKNOWN_FAIL;
        }
        EndpointState state = latestEndpointState(proxyInfo);
        if (state == null) {
            return ProxyCheckDiagnostics.normalize(fallbackDiagnostic);
        }
        return state.lastDiagnostic;
    }

    static boolean hasFreshUsableSuccess(SharedConfig.ProxyInfo proxyInfo, long now) {
        return usableSuccessRemainingMs(proxyInfo, now) > 0;
    }

    static long usableSuccessRemainingMs(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return 0;
        }
        long visibleRemaining = ProxyStatusMirror.visibleUsableSuccessRemainingMs(proxyInfo, now, USABLE_SUCCESS_HOLD_MS);
        long exactRemaining = usableSuccessRemainingMs(ProxyEndpointKey.exact(proxyInfo), now);
        long networkRemaining = usableSuccessRemainingMs(ProxyEndpointKey.network(proxyInfo), now);
        return Math.max(visibleRemaining, Math.max(exactRemaining, networkRemaining));
    }

    static String lastUsablePhase(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return ProxyCheckDiagnostics.UNKNOWN_FAIL;
        }
        String visible = ProxyStatusMirror.diagnostic(proxyInfo);
        if (ProxyStatusMirror.visibleUsableSuccessRemainingMs(proxyInfo, now, USABLE_SUCCESS_HOLD_MS) > 0
                && ProxyPhasePolicy.isProxyUsableSuccessPhase(visible)) {
            return visible;
        }
        EndpointState exactState = endpointStates.get(ProxyEndpointKey.exact(proxyInfo));
        EndpointState networkState = endpointStates.get(ProxyEndpointKey.network(proxyInfo));
        EndpointState state = freshestUsableState(exactState, networkState, now);
        if (state != null && ProxyPhasePolicy.isProxyUsableSuccessPhase(state.lastUsablePhase)) {
            return state.lastUsablePhase;
        }
        return ProxyCheckDiagnostics.UNKNOWN_FAIL;
    }

    static boolean shouldShadowFailureByUsableSuccess(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        if (!ProxyPhasePolicy.isFailure(normalized)
                || !hasFreshUsableSuccess(proxyInfo, now)
                || failureNeverShadowedByUsableSuccess(normalized)) {
            return false;
        }
        if (!failureUsesPostSuccessShadowBudget(normalized)) {
            return true;
        }
        EndpointState state = endpointStateForUsableHold(proxyInfo, normalized, now);
        if (state == null || state.postSuccessDataPathShadowCount >= POST_SUCCESS_DATA_PATH_SHADOWS) {
            return false;
        }
        state.postSuccessDataPathShadowCount++;
        logControl("decision=post_success_shadow_budget phase=" + normalized + " endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " used=" + state.postSuccessDataPathShadowCount + " limit=" + POST_SUCCESS_DATA_PATH_SHADOWS);
        return true;
    }

    static boolean shouldHoldFailureByUsableSuccess(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        if (!ProxyPhasePolicy.isFailure(normalized)
                || !hasFreshUsableSuccess(proxyInfo, now)
                || failureNeverShadowedByUsableSuccess(normalized)) {
            return false;
        }
        if (!failureUsesPostSuccessShadowBudget(normalized)) {
            return true;
        }
        EndpointState state = endpointStateForUsableHold(proxyInfo, normalized, now);
        return state != null && state.postSuccessDataPathShadowCount < POST_SUCCESS_DATA_PATH_SHADOWS;
    }

    static boolean rememberPostSuccessDataPathShadow(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (!hasFreshUsableSuccess(proxyInfo, now)) {
            return false;
        }
        String exactKey = ProxyEndpointKey.exact(proxyInfo);
        if (exactKey == null) {
            return false;
        }
        EndpointState state = endpointStateForKey(exactKey);
        if (state.postSuccessDataPathShadowCount >= POST_SUCCESS_DATA_PATH_SHADOWS) {
            return false;
        }
        state.postSuccessDataPathShadowCount++;
        logControl("decision=post_success_shadow_budget phase=" + ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE + " endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " used=" + state.postSuccessDataPathShadowCount + " limit=" + POST_SUCCESS_DATA_PATH_SHADOWS);
        return true;
    }

    static long lastUsableSuccessAgeMs(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return -1;
        }
        long exactTime = lastUsableSuccessTime(ProxyEndpointKey.exact(proxyInfo));
        long networkTime = lastUsableSuccessTime(ProxyEndpointKey.network(proxyInfo));
        long lastTime = Math.max(exactTime, networkTime);
        if (lastTime <= 0) {
            return -1;
        }
        return Math.max(0, now - lastTime);
    }

    static boolean isEndpointRotatedAway(SharedConfig.ProxyInfo proxyInfo, long now) {
        if (proxyInfo == null) {
            return false;
        }
        EndpointState state = endpointStates.get(ProxyEndpointKey.exact(proxyInfo));
        return state != null
                && state.lifecycle == EndpointLifecycle.ROTATED_AWAY
                && state.rotatedAwayUntil > now;
    }

    static void quarantineExactEndpoint(SharedConfig.ProxyInfo proxyInfo, String phase, long now) {
        String exactKey = ProxyEndpointKey.exact(proxyInfo);
        if (exactKey == null) {
            return;
        }
        String normalized = ProxyCheckDiagnostics.normalize(phase);
        EndpointState state = endpointStateForKey(exactKey);
        state.lifecycle = EndpointLifecycle.ROTATED_AWAY;
        state.usableSuccessUntil = 0;
        state.lastDiagnostic = normalized;
        state.lastCheckTime = now;
        long rotatedAwayHoldMs = rotatedAwayHoldMs(normalized);
        state.rotatedAwayUntil = now + rotatedAwayHoldMs;
        if (state.consecutiveFailures <= 0) {
            state.consecutiveFailures = 1;
        }
        long quarantineUntil = now + failureBackoffMs(normalized, state.consecutiveFailures);
        if (state.nextCheckTime < quarantineUntil) {
            state.nextCheckTime = quarantineUntil;
        }
        logControl("decision=quarantine_exact endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " phase=" + normalized + " hold_ms=" + rotatedAwayHoldMs);
    }

    static void ignoreEndpointTelemetry(String endpointKey, long now) {
        ignoreEndpointTelemetry(endpointKey, now, ProxyCheckDiagnostics.UNKNOWN_FAIL);
    }

    static void ignoreEndpointTelemetry(String endpointKey, long now, String phase) {
        if (endpointKey == null || endpointKey.length() == 0) {
            return;
        }
        long rotatedAwayHoldMs = rotatedAwayHoldMs(ProxyCheckDiagnostics.normalize(phase));
        pruneEndpointTelemetryIgnores(now);
        endpointTelemetryIgnoreUntil.put(endpointKey, now + rotatedAwayHoldMs);
        logControl("decision=rotated_away_ignore endpoint=" + endpointKey + " phase=" + ProxyCheckDiagnostics.normalize(phase) + " hold_ms=" + rotatedAwayHoldMs);
    }

    static boolean shouldIgnoreEndpointTelemetry(String endpointKey, long now) {
        if (endpointKey == null || endpointKey.length() == 0) {
            return false;
        }
        pruneEndpointTelemetryIgnores(now);
        for (String ignoredKey : endpointTelemetryIgnoreUntil.keySet()) {
            Long ignoreUntil = endpointTelemetryIgnoreUntil.get(ignoredKey);
            if (ignoreUntil != null
                    && ignoreUntil > now
                    && ProxyEndpointKey.sameTelemetryEndpointKey(endpointKey, ignoredKey)) {
                return true;
            }
        }
        return false;
    }

    static void clearRotatedAwayTelemetry() {
        endpointTelemetryIgnoreUntil.clear();
    }

    static EndpointFailureResult rememberLiveFailure(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        String key = ProxyEndpointKey.forPhase(proxyInfo, normalized);
        if (key == null) {
            return EndpointFailureResult.noop(normalized);
        }
        EndpointState state = endpointStateForKey(key);
        if (normalized.equals(state.lastDiagnostic) && now - state.lastCheckTime < PROXY_CHECK_LIVE_FAILURE_DEDUP_MS) {
            logControl("decision=live_failure_dedup endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " phase=" + normalized);
            return EndpointFailureResult.dedup(normalized, state.consecutiveFailures, state.rotationFailures);
        }
        return rememberEndpointFailure(state, proxyInfo, normalized, now, "live_failure");
    }

    static void rememberConnected(SharedConfig.ProxyInfo proxyInfo, long now) {
        String key = ProxyEndpointKey.exact(proxyInfo);
        if (key == null) {
            return;
        }
        rememberEndpointConnected(endpointStateForKey(key), ProxyCheckDiagnostics.OK, now, false);
        String networkKey = ProxyEndpointKey.network(proxyInfo);
        if (networkKey != null && !networkKey.equals(key)) {
            rememberEndpointConnected(endpointStateForKey(networkKey), ProxyCheckDiagnostics.OK, now, false);
        }
    }

    static void clearEndpointBackoff(SharedConfig.ProxyInfo proxyInfo, String phase, long now) {
        String exactKey = ProxyEndpointKey.exact(proxyInfo);
        if (exactKey == null) {
            return;
        }
        rememberEndpointConnected(endpointStateForKey(exactKey), phase, now, true);
        String networkKey = ProxyEndpointKey.network(proxyInfo);
        if (networkKey != null && !networkKey.equals(exactKey)) {
            rememberEndpointConnected(endpointStateForKey(networkKey), phase, now, true);
        }
        logControl("decision=clear_backoff phase=" + phase + " endpoint=" + ProxyEndpointKey.endpoint(proxyInfo));
    }

    static EndpointFailureResult rememberProxyCheckFailure(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        String key = ProxyEndpointKey.forPhase(proxyInfo, normalized);
        if (key == null) {
            key = ProxyEndpointKey.exact(proxyInfo);
        }
        if (key == null) {
            return EndpointFailureResult.noop(normalized);
        }
        return rememberEndpointFailure(endpointStateForKey(key), proxyInfo, normalized, now, ProxyConnectionEvent.SOURCE_PROXY_CHECK);
    }

    static EndpointFailureResult lastFailureResult(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        String key = ProxyEndpointKey.forPhase(proxyInfo, normalized);
        if (key == null) {
            key = ProxyEndpointKey.exact(proxyInfo);
        }
        if (key == null) {
            return EndpointFailureResult.noop(normalized);
        }
        EndpointState state = endpointStates.get(key);
        if (state == null) {
            return EndpointFailureResult.noop(normalized);
        }
        boolean insideWindow = state.rotationFailureWindowStartTime != 0
                && now - state.rotationFailureWindowStartTime <= PUNITIVE_FAILURE_WINDOW_MS;
        boolean oneShotTerminal = ProxyPhasePolicy.isOneShotTerminal(normalized);
        boolean rotationAllowed = ProxyPhasePolicy.canRotate(normalized)
                && (oneShotTerminal || (insideWindow && state.rotationFailures >= PUNITIVE_FAILURES_TO_ROTATE));
        return new EndpointFailureResult(normalized, state.consecutiveFailures, state.rotationFailures, rotationAllowed, false);
    }

    private static long usableSuccessRemainingMs(String key, long now) {
        EndpointState state = endpointStates.get(key);
        if (state == null || state.usableSuccessUntil <= now) {
            return 0;
        }
        return state.usableSuccessUntil - now;
    }

    private static long lastUsableSuccessTime(String key) {
        EndpointState state = endpointStates.get(key);
        return state == null ? 0 : state.lastUsableSuccessTime;
    }

    private static EndpointState endpointStateForUsableHold(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now) {
        if (proxyInfo == null) {
            return null;
        }
        String key = ProxyEndpointKey.forPhase(proxyInfo, diagnostic);
        if (key == null) {
            key = ProxyEndpointKey.exact(proxyInfo);
        }
        if (key == null) {
            return null;
        }
        EndpointState state = endpointStateForKey(key);
        if (state.usableSuccessUntil <= now) {
            long remainingMs = usableSuccessRemainingMs(proxyInfo, now);
            if (remainingMs <= 0) {
                return null;
            }
            state.usableSuccessUntil = now + remainingMs;
        }
        return state;
    }

    private static boolean failureUsesPostSuccessShadowBudget(String diagnostic) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        return ProxyCheckDiagnostics.TCP_CONNECTED_NO_PONG.equals(normalized)
                || ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE.equals(normalized)
                || ProxyCheckDiagnostics.POST_HANDSHAKE_NO_APPDATA.equals(normalized);
    }

    private static boolean failureNeverShadowedByUsableSuccess(String diagnostic) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        return ProxyCheckDiagnostics.DROPPED_EARLY_AFTER_APPDATA.equals(normalized)
                || ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA.equals(normalized);
    }

    private static EndpointState freshestUsableState(EndpointState first, EndpointState second, long now) {
        boolean firstFresh = first != null
                && first.usableSuccessUntil > now
                && ProxyPhasePolicy.isProxyUsableSuccessPhase(first.lastUsablePhase);
        boolean secondFresh = second != null
                && second.usableSuccessUntil > now
                && ProxyPhasePolicy.isProxyUsableSuccessPhase(second.lastUsablePhase);
        if (!firstFresh) {
            return secondFresh ? second : null;
        }
        if (!secondFresh) {
            return first;
        }
        return second.lastUsableSuccessTime > first.lastUsableSuccessTime ? second : first;
    }

    private static void rememberEndpointConnected(EndpointState state, String diagnostic, long now, boolean usableSuccess) {
        state.consecutiveFailures = 0;
        state.rotationFailures = 0;
        state.rotationFailureWindowStartTime = 0;
        state.lifecycle = usableSuccess ? EndpointLifecycle.USABLE : EndpointLifecycle.TESTING;
        state.lastDiagnostic = ProxyCheckDiagnostics.normalize(diagnostic);
        state.lastCheckTime = now;
        state.nextCheckTime = now + PROXY_CHECK_CONNECTED_GRACE_MS;
        state.usableSuccessUntil = usableSuccess ? now + USABLE_SUCCESS_HOLD_MS : 0;
        state.postSuccessDataPathShadowCount = 0;
        state.rotatedAwayUntil = 0;
        if (usableSuccess) {
            state.lastUsableSuccessTime = now;
            state.lastUsablePhase = state.lastDiagnostic;
        }
    }

    private static EndpointFailureResult rememberEndpointFailure(EndpointState state, SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now, String source) {
        state.usableSuccessUntil = 0;
        state.postSuccessDataPathShadowCount = 0;
        state.lifecycle = EndpointLifecycle.DEGRADED;
        state.lastDiagnostic = ProxyCheckDiagnostics.normalize(diagnostic);
        state.lastCheckTime = now;
        state.consecutiveFailures++;
        boolean oneShotTerminal = ProxyPhasePolicy.isOneShotTerminal(state.lastDiagnostic);
        if (ProxyPhasePolicy.canRotate(state.lastDiagnostic)) {
            if (state.rotationFailureWindowStartTime == 0 || now - state.rotationFailureWindowStartTime > PUNITIVE_FAILURE_WINDOW_MS) {
                state.rotationFailureWindowStartTime = now;
                state.rotationFailures = 1;
            } else {
                state.rotationFailures++;
            }
            if (oneShotTerminal && state.rotationFailures < PUNITIVE_FAILURES_TO_ROTATE) {
                state.rotationFailures = PUNITIVE_FAILURES_TO_ROTATE;
            }
        } else {
            state.rotationFailureWindowStartTime = 0;
            state.rotationFailures = 0;
        }
        long backoff = failureBackoffMs(state.lastDiagnostic, state.consecutiveFailures);
        state.nextCheckTime = now + backoff;
        boolean rotationAllowed = ProxyPhasePolicy.canRotate(state.lastDiagnostic)
                && (state.rotationFailures >= PUNITIVE_FAILURES_TO_ROTATE || oneShotTerminal);
        if (rotationAllowed) {
            state.lifecycle = EndpointLifecycle.QUARANTINED;
        }
        String evidence = ProxyPhasePolicy.evidenceForPhase(state.lastDiagnostic);
        logControl("decision=backoff phase=" + state.lastDiagnostic + " evidence=" + evidence + " endpoint=" + ProxyEndpointKey.endpoint(proxyInfo) + " wait_ms=" + backoff + " failures=" + state.consecutiveFailures + " rotation_failures=" + state.rotationFailures + " rotation_allowed=" + rotationAllowed + " source=" + source);
        return new EndpointFailureResult(state.lastDiagnostic, state.consecutiveFailures, state.rotationFailures, rotationAllowed, true);
    }

    private static long failureBackoffMs(String diagnostic, int consecutiveFailures) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        if (isInvalidSecretDiagnostic(normalized)) {
            return INVALID_SECRET_FAILURE_BACKOFF_MS;
        }
        long multiplier = 1L << Math.min(2, Math.max(0, consecutiveFailures - 1));
        return Math.min(PROXY_CHECK_FAILURE_BACKOFF_MAX_MS, PROXY_CHECK_FAILURE_BACKOFF_MS * multiplier);
    }

    private static long rotatedAwayHoldMs(String diagnostic) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        if (isInvalidSecretDiagnostic(normalized)) {
            return INVALID_SECRET_ROTATED_AWAY_HOLD_MS;
        }
        return ROTATED_AWAY_HOLD_MS;
    }

    private static boolean isInvalidSecretDiagnostic(String diagnostic) {
        String normalized = ProxyCheckDiagnostics.normalize(diagnostic);
        return ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN_CONTROL_CHAR.equals(normalized)
                || ProxyCheckDiagnostics.SECRET_PARSE_INVALID_DOMAIN.equals(normalized);
    }

    static int punitiveFailuresToRotate() {
        return PUNITIVE_FAILURES_TO_ROTATE;
    }

    private static EndpointState endpointStateForKey(String key) {
        EndpointState state = endpointStates.get(key);
        if (state == null) {
            state = new EndpointState();
            endpointStates.put(key, state);
        }
        return state;
    }

    private static EndpointState latestEndpointState(SharedConfig.ProxyInfo proxyInfo) {
        EndpointState exactState = endpointStates.get(ProxyEndpointKey.exact(proxyInfo));
        EndpointState networkState = endpointStates.get(ProxyEndpointKey.network(proxyInfo));
        if (exactState == null) {
            return networkState;
        }
        if (networkState == null) {
            return exactState;
        }
        return networkState.lastCheckTime > exactState.lastCheckTime ? networkState : exactState;
    }

    private static EndpointState endpointFailureState(SharedConfig.ProxyInfo proxyInfo) {
        EndpointState exactState = endpointStates.get(ProxyEndpointKey.exact(proxyInfo));
        EndpointState networkState = endpointStates.get(ProxyEndpointKey.network(proxyInfo));
        boolean exactBackoff = exactState != null && exactState.consecutiveFailures > 0;
        boolean networkBackoff = networkState != null && networkState.consecutiveFailures > 0;
        if (!exactBackoff) {
            return networkBackoff ? networkState : null;
        }
        if (!networkBackoff) {
            return exactState;
        }
        return networkState.nextCheckTime > exactState.nextCheckTime ? networkState : exactState;
    }

    private static void pruneEndpointTelemetryIgnores(long now) {
        java.util.Iterator<java.util.Map.Entry<String, Long>> iterator = endpointTelemetryIgnoreUntil.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue() <= now) {
                iterator.remove();
            }
        }
    }

    private static void logControl(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_control " + message);
        }
    }

    static final class EndpointFailureResult {
        final String diagnostic;
        final int consecutiveFailures;
        final int rotationFailures;
        final boolean rotationAllowed;
        final boolean recorded;

        private EndpointFailureResult(String diagnostic, int consecutiveFailures, int rotationFailures, boolean rotationAllowed, boolean recorded) {
            this.diagnostic = ProxyCheckDiagnostics.normalize(diagnostic);
            this.consecutiveFailures = consecutiveFailures;
            this.rotationFailures = rotationFailures;
            this.rotationAllowed = rotationAllowed;
            this.recorded = recorded;
        }

        static EndpointFailureResult noop(String diagnostic) {
            return new EndpointFailureResult(diagnostic, 0, 0, false, false);
        }

        static EndpointFailureResult dedup(String diagnostic, int consecutiveFailures, int rotationFailures) {
            return new EndpointFailureResult(diagnostic, consecutiveFailures, rotationFailures, false, false);
        }
    }

    private static class EndpointState {
        int consecutiveFailures;
        int rotationFailures;
        long rotationFailureWindowStartTime;
        EndpointLifecycle lifecycle = EndpointLifecycle.TESTING;
        String lastDiagnostic = ProxyCheckDiagnostics.UNKNOWN_FAIL;
        String lastUsablePhase = ProxyCheckDiagnostics.UNKNOWN_FAIL;
        long lastCheckTime;
        long nextCheckTime;
        long usableSuccessUntil;
        long lastUsableSuccessTime;
        long rotatedAwayUntil;
        int postSuccessDataPathShadowCount;
    }
}
