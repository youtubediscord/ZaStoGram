package org.telegram.messenger;

import android.os.SystemClock;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

final class ProxyRotationEngine {
    static final int MAX_SWITCHES_PER_WINDOW = 4;
    static final long SWITCH_WINDOW_MS = 60_000L;
    static final long NO_CANDIDATE_COOLDOWN_MS = 60_000L;

    private final RotationCycle cycle = new RotationCycle();
    private Attempt scheduledAttempt;
    private int generation;

    boolean hasScheduledAttempt() {
        return scheduledAttempt != null && !scheduledAttempt.terminal;
    }

    Attempt beginScheduledAttempt(SharedConfig.ProxyInfo currentProxy, long delayMs, String reason) {
        long now = SystemClock.elapsedRealtime();
        generation++;
        String proxyExactKey = ProxyEndpointKey.exact(currentProxy);
        if (proxyExactKey != null) {
            cycle.triedExactKeys.add(proxyExactKey);
        }
        scheduledAttempt = new Attempt(proxyExactKey, generation, now, reason, now + delayMs);
        return scheduledAttempt;
    }

    void cancelScheduledAttempt(String reason) {
        if (scheduledAttempt != null) {
            scheduledAttempt.terminal = true;
            scheduledAttempt = null;
        }
        generation++;
    }

    void onSettingsChanged() {
        cancelScheduledAttempt("settings_changed");
        cycle.reset();
    }

    void onRotationSettingsApplied() {
        cancelScheduledAttempt("rotation_settings_applied");
    }

    void onConnected() {
        cancelScheduledAttempt("connected");
        cycle.reset();
    }

    SwitchDecision completeScheduledAttempt(Attempt attempt, SharedConfig.ProxyInfo currentProxy) {
        long now = SystemClock.elapsedRealtime();
        if (attempt == null || attempt.terminal || attempt != scheduledAttempt) {
            return SwitchDecision.stale("stale_attempt");
        }
        if (attempt.generation != generation) {
            attempt.terminal = true;
            return SwitchDecision.stale("stale_generation");
        }
        String currentExactKey = ProxyEndpointKey.exact(currentProxy);
        if (attempt.proxyExactKey != null && !attempt.proxyExactKey.equals(currentExactKey)) {
            attempt.terminal = true;
            scheduledAttempt = null;
            generation++;
            return SwitchDecision.stale("stale_endpoint");
        }
        if (ProxyRuntimeStateStore.isCurrentProxyUsable(currentProxy)) {
            attempt.terminal = true;
            scheduledAttempt = null;
            generation++;
            return SwitchDecision.held("held_by_usable_success", ProxyRuntimeStateStore.usableSuccessRemainingMs(currentProxy));
        }

        attempt.terminal = true;
        scheduledAttempt = null;
        if (ProxyCheckDiagnostics.CONNECTING_TIMEOUT.equals(attempt.reason)) {
            ProxyHealthStore.EndpointFailureResult failure = ProxyRuntimeStateStore.markEndpointFailure(currentProxy, ProxyCheckDiagnostics.CONNECTING_TIMEOUT);
            if (!failure.rotationAllowed) {
                generation++;
                return SwitchDecision.held("held_by_failure_hysteresis", 0, failure.diagnostic, ProxyPhasePolicy.failureClassForPhase(failure.diagnostic), failure.rotationFailures);
            }
        }
        return selectSwitchCandidate(currentProxy, now);
    }

    void recordSwitch(SharedConfig.ProxyInfo proxyInfo) {
        long now = SystemClock.elapsedRealtime();
        String exactKey = ProxyEndpointKey.exact(proxyInfo);
        if (exactKey != null) {
            cycle.triedExactKeys.add(exactKey);
        }
        pruneSwitchTimes(now);
        cycle.switchTimes.addLast(now);
        generation++;
    }

    private SwitchDecision selectSwitchCandidate(SharedConfig.ProxyInfo currentProxy, long now) {
        if (cycle.noCandidateUntilMs > now) {
            return SwitchDecision.noCandidate("no_candidate", cycle.noCandidateUntilMs - now);
        }
        if (cycle.noCandidateUntilMs != 0) {
            cycle.noCandidateUntilMs = 0;
            cycle.triedExactKeys.clear();
            String currentExactKey = ProxyEndpointKey.exact(currentProxy);
            if (currentExactKey != null) {
                cycle.triedExactKeys.add(currentExactKey);
            }
        }

        pruneSwitchTimes(now);
        if (cycle.switchTimes.size() >= MAX_SWITCHES_PER_WINDOW) {
            cycle.noCandidateUntilMs = now + NO_CANDIDATE_COOLDOWN_MS;
            SwitchDecision decision = SwitchDecision.noCandidate("rate_limited", NO_CANDIDATE_COOLDOWN_MS);
            decision.decision = "rate_limited";
            return decision;
        }

        SharedConfig.ProxyInfo fresh = selectFreshAvailableCandidate();
        if (fresh != null) {
            return SwitchDecision.candidate(fresh, "fresh");
        }

        SharedConfig.ProxyInfo fallback = selectFallbackCandidate(currentProxy);
        if (fallback != null) {
            return SwitchDecision.candidate(fallback, "fallback");
        }

        cycle.noCandidateUntilMs = now + NO_CANDIDATE_COOLDOWN_MS;
        SwitchDecision decision = SwitchDecision.noCandidate("no_candidate", NO_CANDIDATE_COOLDOWN_MS);
        decision.decision = "no_candidate";
        return decision;
    }

    private SharedConfig.ProxyInfo selectFreshAvailableCandidate() {
        List<SharedConfig.ProxyInfo> sortedList = new ArrayList<>(SharedConfig.proxyList);
        Collections.sort(sortedList, (o1, o2) -> Long.compare(o1.ping, o2.ping));
        for (SharedConfig.ProxyInfo info : sortedList) {
            if (!isCandidateAllowed(info) || !info.available || !ProxyRuntimeStateStore.isFresh(info)) {
                continue;
            }
            return info;
        }
        return null;
    }

    private SharedConfig.ProxyInfo selectFallbackCandidate(SharedConfig.ProxyInfo currentProxy) {
        int count = SharedConfig.proxyList.size();
        int currentIndex = currentProxy != null ? SharedConfig.proxyList.indexOf(currentProxy) : -1;
        for (int offset = 1; offset <= count; offset++) {
            int index = (currentIndex + offset + count) % count;
            SharedConfig.ProxyInfo info = SharedConfig.proxyList.get(index);
            if (isCandidateAllowed(info)) {
                return info;
            }
        }
        return null;
    }

    private boolean isCandidateAllowed(SharedConfig.ProxyInfo info) {
        String exactKey = ProxyEndpointKey.exact(info);
        return ProxyRuntimeStateStore.isSwitchableCandidate(info)
                && exactKey != null
                && !cycle.triedExactKeys.contains(exactKey);
    }

    private void pruneSwitchTimes(long now) {
        while (!cycle.switchTimes.isEmpty() && now - cycle.switchTimes.peekFirst() > SWITCH_WINDOW_MS) {
            cycle.switchTimes.removeFirst();
        }
    }

    static final class Attempt {
        final String proxyExactKey;
        final int generation;
        final long startedAtMs;
        final String reason;
        final long timeoutAtMs;
        boolean terminal;

        Attempt(String proxyExactKey, int generation, long startedAtMs, String reason, long timeoutAtMs) {
            this.proxyExactKey = proxyExactKey;
            this.generation = generation;
            this.startedAtMs = startedAtMs;
            this.reason = reason;
            this.timeoutAtMs = timeoutAtMs;
        }
    }

    static final class SwitchDecision {
        SharedConfig.ProxyInfo proxyInfo;
        String decision;
        String phase;
        String failureClass;
        int failures;
        long waitMs;
        boolean stale;
        boolean held;

        private static SwitchDecision candidate(SharedConfig.ProxyInfo proxyInfo, String decision) {
            SwitchDecision result = new SwitchDecision();
            result.proxyInfo = proxyInfo;
            result.decision = decision;
            return result;
        }

        private static SwitchDecision noCandidate(String decision, long waitMs) {
            SwitchDecision result = new SwitchDecision();
            result.decision = decision;
            result.waitMs = waitMs;
            return result;
        }

        private static SwitchDecision held(String decision, long waitMs) {
            SwitchDecision result = noCandidate(decision, waitMs);
            result.held = true;
            return result;
        }

        private static SwitchDecision held(String decision, long waitMs, String phase, String failureClass, int failures) {
            SwitchDecision result = held(decision, waitMs);
            result.phase = phase;
            result.failureClass = failureClass;
            result.failures = failures;
            return result;
        }

        private static SwitchDecision stale(String decision) {
            SwitchDecision result = new SwitchDecision();
            result.decision = decision;
            result.stale = true;
            return result;
        }
    }

    static final class RotationCycle {
        final HashSet<String> triedExactKeys = new HashSet<>();
        final ArrayDeque<Long> switchTimes = new ArrayDeque<>();
        long noCandidateUntilMs;

        void reset() {
            triedExactKeys.clear();
            switchTimes.clear();
            noCandidateUntilMs = 0;
        }
    }
}
