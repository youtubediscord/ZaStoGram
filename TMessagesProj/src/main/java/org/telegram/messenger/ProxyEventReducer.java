package org.telegram.messenger;

import org.telegram.tgnet.ConnectionsManager;

final class ProxyEventReducer {

    private ProxyEventReducer() {
    }

    static ProxyRuntimeStateStore.Decision reduce(ProxyConnectionEvent event) {
        if (event == null) {
            return ProxyRuntimeStateStore.Decision.ignored("ignored_empty_event", ProxyCheckDiagnostics.UNKNOWN_FAIL, "");
        }
        SharedConfig.ProxyInfo currentProxy = SharedConfig.currentProxy;
        String normalizedPhase = ProxyCheckDiagnostics.normalize(event.phase);
        ProxyEndpointVerdict verdict = ProxyPhasePolicy.verdictForEvent(event);
        if (ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE.equals(normalizedPhase)) {
            if (isActiveProxyEvent(event)
                    && currentProxy != null
                    && ProxyEndpointKey.matchesLiveStage(currentProxy, event.endpointKey)) {
                ProxyHealthStore.rememberPostSuccessDataPathShadow(currentProxy, event.timestamp);
                String originName = verdict.originName();
                ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + originName + " account=" + event.account + " phase=" + normalizedPhase + " endpoint=" + event.endpointKey);
                return ProxyRuntimeStateStore.Decision.ignored("shadowed_socket_failure", normalizedPhase, event.endpointKey, verdict);
            }
            return ProxyRuntimeStateStore.Decision.ignored("shadowed_socket_failure", normalizedPhase, event.endpointKey, verdict);
        }
        boolean concretePhase = verdict.isLivePhase()
                || (verdict.isFailure() && !ProxyCheckDiagnostics.UNKNOWN_FAIL.equals(normalizedPhase));
        boolean selectedAccountStage = event.account == UserConfig.selectedAccount;
        boolean terminalExactConfig = verdict.terminalExactConfig;
        String failureClass = verdict.failureClass;
        if (!isActiveProxyEvent(event)) {
            return updateProxyRowOnly(currentProxy, event, terminalExactConfig);
        }
        if (concretePhase && ProxyRuntimeStateStore.shouldIgnoreStaleActivationGeneration(event)) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=ignored_stale_generation source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " activation_generation=" + event.activationGeneration);
            ProxyEndpointVerdict staleVerdict = verdict.withClassification(
                    ProxyEndpointVerdict.LAYER_LIFECYCLE_CANCELLED,
                    ProxyEndpointVerdict.FAILURE_CLASS_STALE_GENERATION_CANCELLED,
                    ProxyPhasePolicy.userTextKeyForFailureClass(ProxyEndpointVerdict.FAILURE_CLASS_STALE_GENERATION_CANCELLED, event.phase));
            return ProxyRuntimeStateStore.Decision.ignored("ignored_stale_generation", event.phase, event.endpointKey, staleVerdict);
        }
        if (concretePhase && ProxyHealthStore.shouldIgnoreEndpointTelemetry(event.endpointKey, event.timestamp)) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=ignored_rotated_away source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return ProxyRuntimeStateStore.Decision.ignored("ignored_rotated_away", event.phase, event.endpointKey, verdict);
        }
        boolean stageTargetsCurrentProxy = currentProxy != null && concretePhase && ProxyEndpointKey.matchesLiveStage(currentProxy, event.endpointKey);
        if (terminalExactConfig && !stageTargetsCurrentProxy) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
            return terminalExactConfigVerdict(currentProxy, event, false);
        }
        if (!stageTargetsCurrentProxy) {
            if (selectedAccountStage && currentProxy != null && concretePhase) {
                ProxyRuntimeStateStore.logControl("decision=ignored_stale_endpoint source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " current=" + ProxyEndpointKey.liveStage(currentProxy));
            }
            return ProxyRuntimeStateStore.Decision.ignored("ignored_stale_endpoint", event.phase, event.endpointKey, verdict);
        }
        if (!ProxyVisibleStateStore.shouldDelayDnsVisiblePhase(event.phase)) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
        }
        ProxyWarmupGate.onProxyLivePhase(event.endpointKey, verdict.phase, event.timestamp);
        if (verdict.usableSuccess) {
            ProxyRuntimeStateStore.markConnectionUsable(currentProxy, event.phase, event.timestamp, event.activationGeneration);
            ProxyRuntimeStateStore.logControl("decision=visible_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + verdict.phase + " layer=" + verdict.layer + " failure_class=" + verdict.failureClass + " action=" + verdict.action + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("visible_usable_success", verdict.phase, event.endpointKey, verdict, false, true, false);
        }
        if (ProxyVisibleStateStore.shouldHoldLivePhaseByUsableSuccess(currentProxy, event)) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_live_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_live_by_usable_success", event.phase, event.endpointKey, verdict, false, false, true);
        }
        if (ProxyVisibleStateStore.shouldShadowFailureByUsableSuccess(currentProxy, event)) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=shadowed_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("shadowed_by_usable_success", event.phase, event.endpointKey, verdict, false, false, true);
        }
        boolean freshUsableSuccess = ProxyHealthStore.hasFreshUsableSuccess(currentProxy, event.timestamp);
        if (!freshUsableSuccess
                && ProxyVisibleStateStore.isCurrentProxyUsable(currentProxy, event.timestamp)
                && verdict.isLivePhase()
                && !verdict.usableSuccess) {
            String heldBy = ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_live_by_current_proxy_usable source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_live_by_current_proxy_usable", event.phase, event.endpointKey, verdict, false, false, true);
        }
        boolean holdFailureByUsableSuccess = ProxyHealthStore.shouldHoldFailureByUsableSuccess(currentProxy, event.phase, event.timestamp);
        if (verdict.canBackoff && freshUsableSuccess && holdFailureByUsableSuccess) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_by_usable_success", event.phase, event.endpointKey, verdict, false, false, true);
        }
        if (verdict.canBackoff && ProxyVisibleStateStore.isCurrentProxyUsable(currentProxy, event.timestamp) && holdFailureByUsableSuccess) {
            String heldBy = ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_by_current_proxy_usable source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_by_current_proxy_usable", event.phase, event.endpointKey, verdict, false, false, true);
        }
        if (isPostSuccessDataPathDegraded(currentProxy, event, verdict, holdFailureByUsableSuccess)) {
            verdict = ProxyPhasePolicy.postSuccessDataPathVerdict(verdict);
            failureClass = verdict.failureClass;
        }
        ProxyRuntimeStateStore.rememberDnsResolveFailurePhase(currentProxy, event.phase, event.timestamp);
        if (ProxyRuntimeStateStore.shouldHoldHostResolveFailureByDnsOutage(currentProxy, event.phase, event.timestamp)) {
            ProxyRuntimeStateStore.logControl("decision=dns_outage_hold source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " host=" + ProxyRuntimeStateStore.dnsHost(currentProxy) + " failures=" + ProxyRuntimeStateStore.dnsOutageFailures(currentProxy, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("dns_outage_hold", event.phase, event.endpointKey, verdict, false, false, true);
        }
        if (ProxyRuntimeStateStore.shouldKeepConnectionNotStartedTelemetryOnlyByDnsOutage(currentProxy, event.phase, event.timestamp)) {
            ProxyRuntimeStateStore.logControl("decision=telemetry_only reason=previous_dns_outage source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " host=" + ProxyRuntimeStateStore.dnsHost(currentProxy) + " failures=" + ProxyRuntimeStateStore.dnsOutageFailures(currentProxy, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, verdict, false, false, false);
        }

        if (ProxyVisibleStateStore.shouldDelayDnsVisiblePhase(event.phase)) {
            if (selectedAccountStage) {
                ProxyVisibleStateStore.scheduleDnsVisiblePhase(currentProxy, event);
            }
            ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " delay_ms=" + ProxyVisibleStateStore.DNS_VISIBLE_DELAY_MS);
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, verdict, false, false, false);
        }

        if (shouldKeepLifecycleFailureTelemetryOnly(event.phase)) {
            ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, verdict, false, false, false);
        }

        boolean visibleChanged = false;
        if (selectedAccountStage && verdict.canOverwriteVisible) {
            if (ProxyVisibleStateStore.shouldHoldVisiblePhaseByFreshFailure(currentProxy, event)) {
                return new ProxyRuntimeStateStore.Decision("held_by_fresh_failure", event.phase, event.endpointKey, verdict, false, false, true);
            }
            if (ProxyVisibleStateStore.shouldCoalesceProbeWait(currentProxy, event)) {
                ProxyRuntimeStateStore.logControl("decision=telemetry_only reason=probe_wait_coalesced source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " probe=" + event.probeKey + " delay_ms=" + ProxyVisibleStateStore.PROBE_WAIT_VISIBLE_REPEAT_MS);
                return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, verdict, false, false, false);
            }
            visibleChanged = ProxyVisibleStateStore.mirrorVisiblePhaseIfAllowed(currentProxy, event, visiblePhaseForVerdict(verdict));
        }

        if (!verdict.canBackoff) {
            ProxyRuntimeStateStore.logControl("decision=visible_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + verdict.phase + " layer=" + verdict.layer + " failure_class=" + verdict.failureClass + " action=" + verdict.action + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("visible_only", verdict.phase, event.endpointKey, verdict, false, visibleChanged, false);
        }
        if (terminalExactConfig) {
            return terminalExactConfigVerdict(currentProxy, event, visibleChanged);
        }

        if (ProxyPhasePolicy.isPunitiveFailure(verdict.phase)) {
            ProxyWarmupGate.onProxyFailure(event.endpointKey, event.phase, event.timestamp);
        }
        ProxyHealthStore.EndpointFailureResult failure = ProxyHealthStore.rememberLiveFailure(currentProxy, event.phase, event.timestamp);
        ProxyRuntimeStateStore.logControl("decision=backoff phase=" + verdict.phase + " layer=" + verdict.layer + " failure_class=" + verdict.failureClass + " confidence=" + verdict.confidence + " action=" + verdict.action + " sticky_until_ms=" + verdict.stickyUntilMs + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey + " failures=" + failure.consecutiveFailures + " rotation_failures=" + failure.rotationFailures + " rotation_allowed=" + failure.rotationAllowed);
        if (verdict.canRotate && failure.rotationAllowed) {
            ProxyRuntimeStateStore.logControl("decision=rotation_trigger phase=" + verdict.phase + " failures=" + failure.rotationFailures + " failure_class=" + failureClass + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey + " probe=" + event.probeKey);
            return ProxyRuntimeStateStore.quarantineAndCancelEndpoint(currentProxy, event.phase, event.endpointKey, event.probeKey, event.timestamp, event.source, event.origin, event.account, event.activationGeneration, visibleChanged);
        }
        if (verdict.canRotate) {
            ProxyRuntimeStateStore.logControl("decision=held_by_failure_hysteresis phase=" + verdict.phase + " failures=" + failure.rotationFailures + " failure_class=" + failureClass + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey);
        }
        return new ProxyRuntimeStateStore.Decision("backoff", verdict.phase, event.endpointKey, verdict, false, visibleChanged, false);
    }

    private static boolean isActiveProxyEvent(ProxyConnectionEvent event) {
        return event != null && ProxyConnectionEvent.isActiveProxyOrigin(event.origin);
    }

    private static ProxyRuntimeStateStore.Decision updateProxyRowOnly(SharedConfig.ProxyInfo currentProxy, ProxyConnectionEvent event, boolean terminalExactConfig) {
        ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
        String normalized = ProxyCheckDiagnostics.normalize(event.phase);
        String targetEndpointKey = event.endpointKey == null || event.endpointKey.length() == 0 ? "" : event.endpointKey;
        String targetProbeKey = event.probeKey == null ? "" : event.probeKey;
        String originName = event.origin == null ? ProxyConnectionEvent.Origin.PROXY_CHECK.wireName : event.origin.wireName;
        String failureClass = ProxyPhasePolicy.failureClassForPhase(normalized);
        ProxyEndpointVerdict verdict = ProxyPhasePolicy.verdictForEvent(event);
        boolean matchesActive = currentProxy != null && ProxyEndpointKey.matchesLiveStage(currentProxy, targetEndpointKey);
        if (terminalExactConfig) {
            ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " row_only=1 active_match=" + (matchesActive ? 1 : 0));
            int proxyCheckCancelled = ProxyCheckScheduler.cancelEndpointAttempts(targetEndpointKey);
            int nativeCancelled = matchesActive ? 0 : ConnectionsManager.cancelProxyEndpointAttempts(targetEndpointKey, targetProbeKey, "terminal_proxy_config_unsupported");
            if (!matchesActive) {
                ProxyHealthStore.ignoreEndpointTelemetry(targetEndpointKey, event.timestamp, normalized);
            }
            ProxyRuntimeStateStore.logControl("decision=cancel_endpoint_attempts phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " proxy_check_cancelled=" + proxyCheckCancelled + " native_cancelled=" + nativeCancelled + " row_only=1");
            ProxyRuntimeStateStore.logControl("decision=terminal_quarantine phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " row_only=1");
            return new ProxyRuntimeStateStore.Decision("proxy_list_only", normalized, targetEndpointKey, verdict, false, false, true);
        }
        String heldBy = ProxyVisibleStateStore.currentProxyHasFreshUsableSuccessOrConnected(currentProxy, event.timestamp)
                ? ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp)
                : "origin_" + originName;
        ProxyRuntimeStateStore.logControl("decision=proxy_list_only source=" + event.source + " origin=" + originName + " account=" + event.account + " phase=" + normalized + " endpoint=" + targetEndpointKey + " held_by=" + heldBy);
        return new ProxyRuntimeStateStore.Decision("proxy_list_only", normalized, targetEndpointKey, verdict, false, false, true);
    }

    private static ProxyRuntimeStateStore.Decision terminalExactConfigVerdict(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event, boolean visibleChanged) {
        String normalized = ProxyCheckDiagnostics.normalize(event.phase);
        String targetEndpointKey = event.endpointKey == null || event.endpointKey.length() == 0 ? ProxyEndpointKey.liveStage(proxyInfo) : event.endpointKey;
        String targetProbeKey = event.probeKey == null ? "" : event.probeKey;
        String originName = event.origin == null ? ProxyConnectionEvent.Origin.ACTIVE_SOCKET.wireName : event.origin.wireName;
        String failureClass = ProxyPhasePolicy.failureClassForPhase(normalized);
        ProxyEndpointVerdict verdict = ProxyPhasePolicy.verdictForEvent(event);
        boolean activeSelected = isActiveProxyEvent(event)
                && proxyInfo != null
                && ProxyEndpointKey.matchesLiveStage(proxyInfo, targetEndpointKey);
        boolean currentUsable = activeSelected && ProxyVisibleStateStore.isCurrentProxyUsable(proxyInfo, event.timestamp);
        if (currentUsable) {
            ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " held_by=" + ProxyVisibleStateStore.heldByCurrentProxyPhase(proxyInfo, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("terminal_proxy_config_unsupported", normalized, targetEndpointKey, verdict, false, false, true);
        }
        ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " active_selected=" + activeSelected);
        if (activeSelected) {
            ProxyWarmupGate.onProxyFailure(targetEndpointKey, normalized, event.timestamp);
            return ProxyRuntimeStateStore.quarantineAndCancelEndpoint(proxyInfo, normalized, targetEndpointKey, targetProbeKey, event.timestamp, event.source, event.origin, event.account, event.activationGeneration, visibleChanged);
        }
        ProxyHealthStore.ignoreEndpointTelemetry(targetEndpointKey, event.timestamp, normalized);
        int proxyCheckCancelled = ProxyCheckScheduler.cancelEndpointAttempts(targetEndpointKey);
        int nativeCancelled = ConnectionsManager.cancelProxyEndpointAttempts(targetEndpointKey, targetProbeKey, "terminal_proxy_config_unsupported");
        ProxyRuntimeStateStore.logControl("decision=cancel_endpoint_attempts phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " proxy_check_cancelled=" + proxyCheckCancelled + " native_cancelled=" + nativeCancelled);
        ProxyRuntimeStateStore.logControl("decision=terminal_quarantine phase=" + normalized + " failure_class=" + failureClass + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey);
        return new ProxyRuntimeStateStore.Decision("terminal_proxy_config_unsupported", normalized, targetEndpointKey, verdict, false, false, true);
    }

    private static boolean shouldKeepLifecycleFailureTelemetryOnly(String phase) {
        String normalized = ProxyCheckDiagnostics.normalize(phase);
        return ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED.equals(normalized)
                || ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT.equals(normalized);
    }

    private static boolean isPostSuccessDataPathDegraded(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event, ProxyEndpointVerdict verdict, boolean holdFailureByUsableSuccess) {
        return verdict != null
                && ProxyCheckDiagnostics.MTPROXY_PACKET_SENT_NO_RESPONSE.equals(verdict.phase)
                && !holdFailureByUsableSuccess
                && ProxyPhasePolicy.isProxyUsableSuccessPhase(ProxyHealthStore.lastUsablePhase(proxyInfo, event.timestamp));
    }

    private static String visiblePhaseForVerdict(ProxyEndpointVerdict verdict) {
        if (verdict != null
                && ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED.equals(verdict.failureClass)) {
            return ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA;
        }
        return verdict == null ? ProxyCheckDiagnostics.UNKNOWN_FAIL : verdict.phase;
    }
}
