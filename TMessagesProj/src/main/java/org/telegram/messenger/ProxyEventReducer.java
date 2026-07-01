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
        if (ProxyCheckDiagnostics.SHADOWED_SOCKET_FAILURE.equals(normalizedPhase)) {
            if (isActiveProxyEvent(event)
                    && currentProxy != null
                    && ProxyEndpointKey.matchesLiveStage(currentProxy, event.endpointKey)) {
                ProxyHealthStore.rememberPostSuccessDataPathShadow(currentProxy, event.timestamp);
                String originName = event.origin == null ? ProxyConnectionEvent.Origin.ACTIVE_PROXY.wireName : event.origin.wireName;
                ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + originName + " account=" + event.account + " phase=" + normalizedPhase + " endpoint=" + event.endpointKey);
                return ProxyRuntimeStateStore.Decision.ignored("shadowed_socket_failure", normalizedPhase, event.endpointKey);
            }
            return ProxyRuntimeStateStore.Decision.ignored("shadowed_socket_failure", normalizedPhase, event.endpointKey);
        }
        boolean concretePhase = ProxyPhasePolicy.isLivePhase(normalizedPhase)
                || (ProxyPhasePolicy.isFailure(normalizedPhase) && !ProxyCheckDiagnostics.UNKNOWN_FAIL.equals(normalizedPhase));
        boolean selectedAccountStage = event.account == UserConfig.selectedAccount;
        boolean terminalExactConfig = ProxyPhasePolicy.terminalExactConfig(event.phase);
        String evidence = ProxyPhasePolicy.evidenceForPhase(event.phase);
        if (!isActiveProxyEvent(event)) {
            return updateProxyRowOnly(currentProxy, event, terminalExactConfig);
        }
        if (concretePhase && ProxyHealthStore.shouldIgnoreEndpointTelemetry(event.endpointKey, event.timestamp)) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=ignored_rotated_away source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return ProxyRuntimeStateStore.Decision.ignored("ignored_rotated_away", event.phase, event.endpointKey);
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
            return ProxyRuntimeStateStore.Decision.ignored("ignored_stale_endpoint", event.phase, event.endpointKey);
        }
        if (!ProxyVisibleStateStore.shouldDelayDnsVisiblePhase(event.phase)) {
            ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
        }
        ProxyWarmupGate.onProxyLivePhase(event.endpointKey, event.phase, event.timestamp);
        if (ProxyPhasePolicy.isProxyUsableSuccessPhase(event.phase)) {
            ProxyRuntimeStateStore.markConnectionUsable(currentProxy, event.phase, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=visible_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("visible_usable_success", event.phase, event.endpointKey, false, true, false);
        }
        if (ProxyVisibleStateStore.shouldHoldLivePhaseByUsableSuccess(currentProxy, event)) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_live_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_live_by_usable_success", event.phase, event.endpointKey, false, false, true);
        }
        if (ProxyVisibleStateStore.shouldShadowFailureByUsableSuccess(currentProxy, event)) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=shadowed_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("shadowed_by_usable_success", event.phase, event.endpointKey, false, false, true);
        }
        boolean freshUsableSuccess = ProxyHealthStore.hasFreshUsableSuccess(currentProxy, event.timestamp);
        if (!freshUsableSuccess
                && ProxyVisibleStateStore.isCurrentProxyUsable(currentProxy, event.timestamp)
                && ProxyPhasePolicy.isLivePhase(event.phase)
                && !ProxyPhasePolicy.isProxyUsableSuccessPhase(event.phase)) {
            String heldBy = ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_live_by_current_proxy_usable source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_live_by_current_proxy_usable", event.phase, event.endpointKey, false, false, true);
        }
        boolean holdFailureByUsableSuccess = ProxyHealthStore.shouldHoldFailureByUsableSuccess(currentProxy, event.phase, event.timestamp);
        if (ProxyPhasePolicy.canBackoff(event.phase) && freshUsableSuccess && holdFailureByUsableSuccess) {
            String heldBy = ProxyVisibleStateStore.heldByUsablePhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_by_usable_success source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_by_usable_success", event.phase, event.endpointKey, false, false, true);
        }
        if (ProxyPhasePolicy.canBackoff(event.phase) && ProxyVisibleStateStore.isCurrentProxyUsable(currentProxy, event.timestamp) && holdFailureByUsableSuccess) {
            String heldBy = ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp);
            ProxyRuntimeStateStore.logControl("decision=held_by_current_proxy_usable source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " held_by=" + heldBy);
            return new ProxyRuntimeStateStore.Decision("held_by_current_proxy_usable", event.phase, event.endpointKey, false, false, true);
        }
        ProxyRuntimeStateStore.rememberDnsResolveFailurePhase(currentProxy, event.phase, event.timestamp);
        if (ProxyRuntimeStateStore.shouldHoldHostResolveFailureByDnsOutage(currentProxy, event.phase, event.timestamp)) {
            ProxyRuntimeStateStore.logControl("decision=dns_outage_hold source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " host=" + ProxyRuntimeStateStore.dnsHost(currentProxy) + " failures=" + ProxyRuntimeStateStore.dnsOutageFailures(currentProxy, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("dns_outage_hold", event.phase, event.endpointKey, false, false, true);
        }
        if (ProxyRuntimeStateStore.shouldKeepConnectionNotStartedTelemetryOnlyByDnsOutage(currentProxy, event.phase, event.timestamp)) {
            ProxyRuntimeStateStore.logControl("decision=telemetry_only reason=previous_dns_outage source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " host=" + ProxyRuntimeStateStore.dnsHost(currentProxy) + " failures=" + ProxyRuntimeStateStore.dnsOutageFailures(currentProxy, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, false, false, false);
        }

        if (ProxyVisibleStateStore.shouldDelayDnsVisiblePhase(event.phase)) {
            if (selectedAccountStage) {
                ProxyVisibleStateStore.scheduleDnsVisiblePhase(currentProxy, event);
            }
            ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey + " delay_ms=" + ProxyVisibleStateStore.DNS_VISIBLE_DELAY_MS);
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, false, false, false);
        }

        if (shouldKeepLifecycleFailureTelemetryOnly(event.phase)) {
            ProxyRuntimeStateStore.logControl("decision=telemetry_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("telemetry_only", event.phase, event.endpointKey, false, false, false);
        }

        boolean visibleChanged = false;
        if (selectedAccountStage && ProxyPhasePolicy.canOverwriteVisible(event.phase)) {
            if (ProxyVisibleStateStore.shouldHoldVisiblePhaseByFreshFailure(currentProxy, event)) {
                return new ProxyRuntimeStateStore.Decision("held_by_fresh_failure", event.phase, event.endpointKey, false, false, true);
            }
            visibleChanged = ProxyVisibleStateStore.mirrorVisiblePhaseIfAllowed(currentProxy, event);
        }

        if (!ProxyPhasePolicy.canBackoff(event.phase)) {
            ProxyRuntimeStateStore.logControl("decision=visible_only source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " phase=" + event.phase + " endpoint=" + event.endpointKey);
            return new ProxyRuntimeStateStore.Decision("visible_only", event.phase, event.endpointKey, false, visibleChanged, false);
        }
        if (terminalExactConfig) {
            return terminalExactConfigVerdict(currentProxy, event, visibleChanged);
        }

        if (ProxyPhasePolicy.isPunitiveFailure(event.phase)) {
            ProxyWarmupGate.onProxyFailure(event.endpointKey, event.phase, event.timestamp);
        }
        ProxyHealthStore.EndpointFailureResult failure = ProxyHealthStore.rememberLiveFailure(currentProxy, event.phase, event.timestamp);
        ProxyRuntimeStateStore.logControl("decision=backoff phase=" + event.phase + " evidence=" + evidence + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey + " failures=" + failure.consecutiveFailures + " rotation_failures=" + failure.rotationFailures + " rotation_allowed=" + failure.rotationAllowed);
        if (ProxyPhasePolicy.canRotate(event.phase) && failure.rotationAllowed) {
            ProxyRuntimeStateStore.logControl("decision=rotation_trigger phase=" + event.phase + " failures=" + failure.rotationFailures + " evidence=" + evidence + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey + " probe=" + event.probeKey);
            return ProxyRuntimeStateStore.quarantineAndCancelEndpoint(currentProxy, event.phase, event.endpointKey, event.probeKey, event.timestamp, event.source, event.origin, event.account, visibleChanged);
        }
        if (ProxyPhasePolicy.canRotate(event.phase)) {
            ProxyRuntimeStateStore.logControl("decision=held_by_failure_hysteresis phase=" + event.phase + " failures=" + failure.rotationFailures + " evidence=" + evidence + " source=" + event.source + " origin=" + event.origin.wireName + " account=" + event.account + " endpoint=" + event.endpointKey);
        }
        return new ProxyRuntimeStateStore.Decision("backoff", event.phase, event.endpointKey, false, visibleChanged, false);
    }

    private static boolean isActiveProxyEvent(ProxyConnectionEvent event) {
        return event != null && event.origin == ProxyConnectionEvent.Origin.ACTIVE_PROXY;
    }

    private static ProxyRuntimeStateStore.Decision updateProxyRowOnly(SharedConfig.ProxyInfo currentProxy, ProxyConnectionEvent event, boolean terminalExactConfig) {
        ProxyVisibleStateStore.clearPendingDnsVisiblePhase(event.endpointKey, event.timestamp);
        String normalized = ProxyCheckDiagnostics.normalize(event.phase);
        String targetEndpointKey = event.endpointKey == null || event.endpointKey.length() == 0 ? "" : event.endpointKey;
        String targetProbeKey = event.probeKey == null ? "" : event.probeKey;
        String originName = event.origin == null ? ProxyConnectionEvent.Origin.PROXY_CHECK.wireName : event.origin.wireName;
        String evidence = ProxyPhasePolicy.evidenceForPhase(normalized);
        boolean matchesActive = currentProxy != null && ProxyEndpointKey.matchesLiveStage(currentProxy, targetEndpointKey);
        if (terminalExactConfig) {
            ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " row_only=1 active_match=" + (matchesActive ? 1 : 0));
            int proxyCheckCancelled = ProxyCheckScheduler.cancelEndpointAttempts(targetEndpointKey);
            int nativeCancelled = matchesActive ? 0 : ConnectionsManager.cancelProxyEndpointAttempts(targetEndpointKey, targetProbeKey, "terminal_proxy_config_unsupported");
            if (!matchesActive) {
                ProxyHealthStore.ignoreEndpointTelemetry(targetEndpointKey, event.timestamp, normalized);
            }
            ProxyRuntimeStateStore.logControl("decision=cancel_endpoint_attempts phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " proxy_check_cancelled=" + proxyCheckCancelled + " native_cancelled=" + nativeCancelled + " row_only=1");
            ProxyRuntimeStateStore.logControl("decision=terminal_quarantine phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " row_only=1");
            return new ProxyRuntimeStateStore.Decision("proxy_list_only", normalized, targetEndpointKey, false, false, true);
        }
        String heldBy = ProxyVisibleStateStore.currentProxyHasFreshUsableSuccessOrConnected(currentProxy, event.timestamp)
                ? ProxyVisibleStateStore.heldByCurrentProxyPhase(currentProxy, event.timestamp)
                : "origin_" + originName;
        ProxyRuntimeStateStore.logControl("decision=proxy_list_only source=" + event.source + " origin=" + originName + " account=" + event.account + " phase=" + normalized + " endpoint=" + targetEndpointKey + " held_by=" + heldBy);
        return new ProxyRuntimeStateStore.Decision("proxy_list_only", normalized, targetEndpointKey, false, false, true);
    }

    private static ProxyRuntimeStateStore.Decision terminalExactConfigVerdict(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent event, boolean visibleChanged) {
        String normalized = ProxyCheckDiagnostics.normalize(event.phase);
        String targetEndpointKey = event.endpointKey == null || event.endpointKey.length() == 0 ? ProxyEndpointKey.liveStage(proxyInfo) : event.endpointKey;
        String targetProbeKey = event.probeKey == null ? "" : event.probeKey;
        String originName = event.origin == null ? ProxyConnectionEvent.Origin.ACTIVE_PROXY.wireName : event.origin.wireName;
        String evidence = ProxyPhasePolicy.evidenceForPhase(normalized);
        boolean activeSelected = isActiveProxyEvent(event)
                && proxyInfo != null
                && ProxyEndpointKey.matchesLiveStage(proxyInfo, targetEndpointKey);
        boolean currentUsable = activeSelected && ProxyVisibleStateStore.isCurrentProxyUsable(proxyInfo, event.timestamp);
        if (currentUsable) {
            ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " held_by=" + ProxyVisibleStateStore.heldByCurrentProxyPhase(proxyInfo, event.timestamp));
            return new ProxyRuntimeStateStore.Decision("terminal_proxy_config_unsupported", normalized, targetEndpointKey, false, false, true);
        }
        ProxyRuntimeStateStore.logControl("decision=terminal_proxy_config_unsupported phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " active_selected=" + activeSelected);
        if (activeSelected) {
            ProxyWarmupGate.onProxyFailure(targetEndpointKey, normalized, event.timestamp);
            return ProxyRuntimeStateStore.quarantineAndCancelEndpoint(proxyInfo, normalized, targetEndpointKey, targetProbeKey, event.timestamp, event.source, event.origin, event.account, visibleChanged);
        }
        ProxyHealthStore.ignoreEndpointTelemetry(targetEndpointKey, event.timestamp, normalized);
        int proxyCheckCancelled = ProxyCheckScheduler.cancelEndpointAttempts(targetEndpointKey);
        int nativeCancelled = ConnectionsManager.cancelProxyEndpointAttempts(targetEndpointKey, targetProbeKey, "terminal_proxy_config_unsupported");
        ProxyRuntimeStateStore.logControl("decision=cancel_endpoint_attempts phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey + " proxy_check_cancelled=" + proxyCheckCancelled + " native_cancelled=" + nativeCancelled);
        ProxyRuntimeStateStore.logControl("decision=terminal_quarantine phase=" + normalized + " evidence=" + evidence + " source=" + event.source + " origin=" + originName + " account=" + event.account + " endpoint=" + targetEndpointKey + " probe=" + targetProbeKey);
        return new ProxyRuntimeStateStore.Decision("terminal_proxy_config_unsupported", normalized, targetEndpointKey, false, false, true);
    }

    private static boolean shouldKeepLifecycleFailureTelemetryOnly(String phase) {
        String normalized = ProxyCheckDiagnostics.normalize(phase);
        return ProxyCheckDiagnostics.BACKGROUND_HANDSHAKE_ABORTED.equals(normalized)
                || ProxyCheckDiagnostics.DNS_NEGATIVE_CACHE_HIT.equals(normalized);
    }
}
