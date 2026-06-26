#!/usr/bin/env python3
from pathlib import Path
import re
import sys

from mtproxy_phase_contract import ENDPOINT_EXACT, ENDPOINT_NETWORK, endpoint_key_phases, rotation_phases


ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = ROOT / "TMessagesProj/src/main/java/org/telegram"
MESSENGER = JAVA_ROOT / "messenger"

ENDPOINT_KEY = MESSENGER / "ProxyEndpointKey.java"
EVENT = MESSENGER / "ProxyConnectionEvent.java"
POLICY = MESSENGER / "ProxyPhasePolicy.java"
STORE = MESSENGER / "ProxyRuntimeStateStore.java"
HEALTH = MESSENGER / "ProxyHealthStore.java"
STATUS = MESSENGER / "ProxyStatusMirror.java"
SCHEDULER = MESSENGER / "ProxyCheckScheduler.java"
ROTATION = MESSENGER / "ProxyRotationController.java"
ENGINE = MESSENGER / "ProxyRotationEngine.java"
CONNECTIONS = JAVA_ROOT / "tgnet/ConnectionsManager.java"
DIAGNOSTICS = MESSENGER / "ProxyCheckDiagnostics.java"


def read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require_file(path: Path, failures: list[str]) -> str:
    text = read(path)
    if not text:
        failures.append(f"{path.relative_to(ROOT)}: missing control-plane file")
    return text


def require(text: str, needle: str, message: str, failures: list[str]) -> None:
    if needle not in text:
        failures.append(message)


def require_not(text: str, needle: str, message: str, failures: list[str]) -> None:
    if needle in text:
        failures.append(message)


def phase_return(policy: str, constant: str) -> str:
    case = f"case ProxyCheckDiagnostics.{constant}:"
    start = policy.find(case)
    if start == -1:
        return ""
    end = policy.find("return ", start)
    if end == -1:
        return ""
    semicolon = policy.find(";", end)
    return policy[end:semicolon + 1] if semicolon != -1 else policy[end:]


def main() -> int:
    failures: list[str] = []

    endpoint_key = require_file(ENDPOINT_KEY, failures)
    event = require_file(EVENT, failures)
    policy = require_file(POLICY, failures)
    store = require_file(STORE, failures)
    health = require_file(HEALTH, failures)
    status = require_file(STATUS, failures)
    scheduler = read(SCHEDULER)
    rotation = read(ROTATION)
    engine = require_file(ENGINE, failures)
    connections = read(CONNECTIONS)
    diagnostics = read(DIAGNOSTICS)

    require(endpoint_key, "public final class ProxyEndpointKey", "ProxyEndpointKey must own endpoint identity helpers", failures)
    require(endpoint_key, "exact(SharedConfig.ProxyInfo", "ProxyEndpointKey must expose exact identity", failures)
    require(endpoint_key, "network(SharedConfig.ProxyInfo", "ProxyEndpointKey must expose host:port/network identity", failures)
    require(endpoint_key, "liveStage(SharedConfig.ProxyInfo", "ProxyEndpointKey must expose native live-stage identity", failures)
    require(endpoint_key, "matchesLiveStage", "ProxyEndpointKey must reject stale endpoint/secret native events", failures)
    require(endpoint_key, "secretDomainForLiveStage", "ProxyEndpointKey must keep ee domain matching with native endpoint keys", failures)

    require(event, "public final class ProxyConnectionEvent", "ProxyConnectionEvent must normalize connection-stage inputs", failures)
    require(event, "SOURCE_NATIVE_STAGE", "ProxyConnectionEvent must distinguish native-stage events", failures)
    require(event, "SOURCE_PROXY_CHECK", "ProxyConnectionEvent must distinguish proxy-check results", failures)
    require(event, "SOURCE_CONNECTED", "ProxyConnectionEvent must distinguish generic connected observations", failures)
    require(event, "SOURCE_CONNECT_START", "ProxyConnectionEvent must distinguish explicit connect attempts", failures)
    require(event, "ProxyCheckDiagnostics.normalize", "ProxyConnectionEvent must normalize phases at construction", failures)

    require(policy, "public final class ProxyPhasePolicy", "ProxyPhasePolicy must centralize phase decisions", failures)
    require(policy, "public enum Kind", "ProxyPhasePolicy must model phase kind", failures)
    require(policy, "public enum KeyScope", "ProxyPhasePolicy must model endpoint key scope", failures)
    require(policy, "usableSuccess", "ProxyPhasePolicy must mark usable-success phases", failures)
    require(policy, "canBackoff", "ProxyPhasePolicy must decide endpoint backoff centrally", failures)
    require(policy, "canRotate", "ProxyPhasePolicy must decide rotation centrally", failures)
    require(policy, "canOverwriteVisible", "ProxyPhasePolicy must decide visible overwrite centrally", failures)
    require(policy, "FIRST_TLS_APP_RECV", "ProxyPhasePolicy must treat first TLS app recv as usable success", failures)
    require(policy, "FIRST_MTPROXY_PACKET_RECV", "ProxyPhasePolicy must treat first MTProxy packet recv as usable success", failures)
    require(policy, "SERVER_HELLO_HMAC_OK", "ProxyPhasePolicy must explicitly classify server hello as handshake only", failures)
    for phase in (
        "CONNECTION_NOT_STARTED",
        "ADMISSION_TIMEOUT",
        "TCP_CONNECT_GATE_TIMEOUT",
        "ENDPOINT_COOLDOWN_TIMEOUT",
        "DNS_COALESCE_TIMEOUT",
    ):
        decision = phase_return(policy, phase)
        if "failure(" not in decision or "false, false" not in decision:
            failures.append(f"ProxyPhasePolicy must classify local scheduler timeout {phase.lower()} as visible failure without backoff or rotation")
    for phase in ("HOST_RESOLVE_FAILED", "HOST_RESOLVE_TIMEOUT", "TCP_NOT_CONNECTED"):
        decision = phase_return(policy, phase)
        if "failure(" not in decision or "true, true" not in decision:
            failures.append(f"ProxyPhasePolicy must keep real network phase {phase.lower()} punitive")

    for phase in sorted(endpoint_key_phases(ENDPOINT_NETWORK)):
        require(policy, f'case ProxyCheckDiagnostics.{phase.upper()}'.replace("NETWORK_BLOCK_SUSPECTED", "NETWORK_BLOCK_SUSPECTED"), f"ProxyPhasePolicy must assign network key scope for {phase}", failures)
    for phase in sorted(rotation_phases()):
        require(policy, phase.upper(), f"ProxyPhasePolicy must include rotation phase {phase}", failures)

    require(store, "public final class ProxyRuntimeStateStore", "ProxyRuntimeStateStore must remain the public runtime control-plane facade", failures)
    require(health, "final class ProxyHealthStore", "ProxyHealthStore must own endpoint health/backoff state", failures)
    require(health, "HashMap<String, EndpointState> endpointStates", "ProxyHealthStore must own endpoint state outside ProxyCheckScheduler and runtime facade", failures)
    require(health, "USABLE_SUCCESS_HOLD_MS", "ProxyHealthStore must keep a short usable-success hold window", failures)
    require(status, "final class ProxyStatusMirror", "ProxyStatusMirror must own runtime ProxyInfo UI-state mirroring", failures)
    require_not(store, "HashMap<String, EndpointState> endpointStates", "ProxyRuntimeStateStore facade must not own endpoint health state directly", failures)
    require(store, "held_by_usable_success", "usable success followed by sibling failure must be held/shadowed", failures)
    require(health, "decision=backoff", "terminal failures without usable success must record backoff decisions in health store", failures)
    require(store, "decision=ignored_stale_endpoint", "stale endpoint/secret native events must be ignored", failures)
    require(store, "decision=visible_only", "non-terminal live stages should be visible-only decisions", failures)
    require(store, "decision=rotation_trigger", "rotation-triggering failures must be explicit decisions", failures)
    require(health, "clearEndpointBackoff", "usable success must clear exact and network endpoint backoff", failures)
    require(store, "shouldScheduleFallback", "rotation must ask the store whether a fallback should be scheduled", failures)
    require(store, "isSwitchableCandidate", "rotation candidate filtering must be delegated to the store", failures)
    require(store, "appliedDiagnosticForProxyCheck", "proxy-check failures must preserve fresh concrete visible phases", failures)
    require(store, "markConnectionStarting", "explicit connect_start must be centralized in runtime store", failures)
    require(store, "ProxyStatusMirror.applyMeasuredProxyCheckResult", "ProxyRuntimeStateStore facade must route measured proxy-check result mirroring through ProxyStatusMirror", failures)
    require(store, "ProxyStatusMirror.copyTransientState", "ProxyRuntimeStateStore facade must route transient state mirroring through ProxyStatusMirror", failures)
    require(status, "applyMeasuredProxyCheckResult", "ProxyStatusMirror must own measured proxy-check result mirroring", failures)
    require(status, "copyTransientState", "ProxyStatusMirror must own transient checking/native ping mirroring", failures)
    require(status, "setChecking", "ProxyStatusMirror must own ProxyInfo.checking writes", failures)
    require(status, "setProxyCheckPingId", "ProxyStatusMirror must own ProxyInfo.proxyCheckPingId writes", failures)
    require(store, "clearTransientState", "ProxyRuntimeStateStore must own transient runtime cleanup", failures)
    require_not(store, ".lastCheckDiagnostic =", "ProxyRuntimeStateStore facade must not write visible diagnostics directly", failures)
    require_not(store, ".lastCheckDiagnosticTime =", "ProxyRuntimeStateStore facade must not write visible diagnostic timestamps directly", failures)
    require_not(store, ".available =", "ProxyRuntimeStateStore facade must not write availability directly", failures)
    require_not(store, ".availableCheckTime =", "ProxyRuntimeStateStore facade must not write availability timestamps directly", failures)
    require_not(store, ".checking =", "ProxyRuntimeStateStore facade must not write checking state directly", failures)
    require_not(store, ".proxyCheckPingId =", "ProxyRuntimeStateStore facade must not write native ping ids directly", failures)
    require_not(store, ".ping =", "ProxyRuntimeStateStore facade must not write measured ping directly", failures)

    require(scheduler, "ProxyRuntimeStateStore.isFresh(proxyInfo)", "ProxyCheckScheduler.isFresh must delegate to ProxyRuntimeStateStore", failures)
    require(scheduler, "ProxyRuntimeStateStore.isEndpointBackedOff(proxyInfo)", "ProxyCheckScheduler.isEndpointBackedOff must delegate to ProxyRuntimeStateStore", failures)
    require(scheduler, "ProxyRuntimeStateStore.markConnected(proxyInfo)", "ProxyCheckScheduler.markConnected must delegate to ProxyRuntimeStateStore", failures)
    require(scheduler, "ProxyRuntimeStateStore.markEndpointFailure(proxyInfo, diagnostic)", "ProxyCheckScheduler.markEndpointFailure must delegate live failures to ProxyRuntimeStateStore", failures)
    require_not(scheduler, "HashMap<String, EndpointState> endpointStates", "ProxyCheckScheduler must not own endpoint backoff state after control-plane split", failures)
    require_not(scheduler, "private static String endpointStateKeyForDiagnostic", "ProxyCheckScheduler must not own phase key-scope policy", failures)
    require_not(scheduler, ".checking =", "ProxyCheckScheduler must not write ProxyInfo.checking directly", failures)
    require_not(scheduler, ".proxyCheckPingId =", "ProxyCheckScheduler must not write ProxyInfo.proxyCheckPingId directly", failures)
    require_not(scheduler, ".available =", "ProxyCheckScheduler must not write ProxyInfo.available directly", failures)
    require_not(scheduler, ".availableCheckTime =", "ProxyCheckScheduler must not write ProxyInfo.availableCheckTime directly", failures)
    require_not(scheduler, ".lastCheckDiagnostic =", "ProxyCheckScheduler must not write ProxyInfo.lastCheckDiagnostic directly", failures)
    require_not(scheduler, ".lastCheckDiagnosticTime =", "ProxyCheckScheduler must not write ProxyInfo.lastCheckDiagnosticTime directly", failures)
    require_not(scheduler, ".ping =", "ProxyCheckScheduler must not write ProxyInfo.ping directly", failures)

    require(connections, "ProxyConnectionEvent.nativeStage", "ConnectionsManager must build a normalized native-stage event", failures)
    require(connections, "ProxyRuntimeStateStore.onNativeStage", "ConnectionsManager must bridge native stages into ProxyRuntimeStateStore", failures)
    require_not(connections, "currentProxy.lastCheckDiagnostic = normalizedDiagnostic", "ConnectionsManager must not write visible diagnostics directly", failures)
    require_not(connections, "ProxyCheckScheduler.markEndpointFailure(currentProxy", "ConnectionsManager must not decide live endpoint backoff directly", failures)

    require(rotation, "ProxyRotationEngine engine = new ProxyRotationEngine()", "ProxyRotationController must delegate rotation choices to ProxyRotationEngine", failures)
    require(rotation, "ROTATION_SETTINGS_CHANGE", "ProxyRotationController must tag rotation-owned proxySettingsChanged events", failures)
    require(rotation, "engine.onRotationSettingsApplied();", "ProxyRotationController must preserve rotation cycle for its own settings notifications", failures)
    require(rotation, "engine.beginScheduledAttempt", "ProxyRotationController must schedule generation-guarded engine attempts", failures)
    require(rotation, "engine.completeScheduledAttempt", "ProxyRotationController must complete scheduled rotation attempts through the engine", failures)
    require(rotation, "ProxyRuntimeStateStore.shouldScheduleFallback", "ProxyRotationController must ask store before scheduling terminal fallback", failures)
    require(rotation, "ProxyRuntimeStateStore.markConnectionStarting(info)", "ProxyRotationController must publish connect_start through the store", failures)
    require_not(rotation, "ProxyCheckDiagnostics.shouldAccelerateProxyRotation(diagnostic)", "ProxyRotationController must not use raw diagnostic rotation policy", failures)
    require_not(rotation, "ProxyCheckDiagnostics.hasFreshFailure(info)", "ProxyRotationController candidate filtering must not duplicate store policy", failures)

    require(engine, "ProxyRuntimeStateStore.isSwitchableCandidate(info)", "ProxyRotationEngine must ask store for switchable candidates", failures)
    require(engine, "ProxyRuntimeStateStore.markEndpointFailure(currentProxy, ProxyCheckDiagnostics.CONNECTING_TIMEOUT)", "ProxyRotationEngine must convert connecting timeout into endpoint backoff", failures)
    require(engine, "triedExactKeys", "ProxyRotationEngine must track endpoints tried in the current cycle", failures)
    require(engine, "MAX_SWITCHES_PER_WINDOW", "ProxyRotationEngine must enforce global rotation rate limits", failures)
    require(engine, "onRotationSettingsApplied", "ProxyRotationEngine must distinguish rotation-owned settings updates from external settings changes", failures)
    rotation_settings_start = engine.find("void onRotationSettingsApplied")
    rotation_settings_end = engine.find("\n    void ", rotation_settings_start + 1)
    rotation_settings_method = engine[rotation_settings_start:rotation_settings_end if rotation_settings_end != -1 else len(engine)]
    if rotation_settings_start == -1 or "cycle.reset()" in rotation_settings_method:
        failures.append("ProxyRotationEngine must not reset rotation cycle for rotation-owned proxySettingsChanged events")

    require(diagnostics, "ProxyPhasePolicy.isFailure", "ProxyCheckDiagnostics must delegate failure classification to ProxyPhasePolicy", failures)
    require(diagnostics, "ProxyPhasePolicy.isLivePhase", "ProxyCheckDiagnostics must delegate live classification to ProxyPhasePolicy", failures)
    require(diagnostics, "ProxyPhasePolicy.shouldAccelerateProxyRotation", "ProxyCheckDiagnostics must delegate rotation classification to ProxyPhasePolicy", failures)
    require(diagnostics, "ProxyPhasePolicy.isProxyUsableSuccessPhase", "ProxyCheckDiagnostics must delegate usable-success classification to ProxyPhasePolicy", failures)

    runtime_write_pattern = re.compile(
        r"\.(?:lastCheckDiagnostic|lastCheckDiagnosticTime|available|availableCheckTime|checking|proxyCheckPingId|ping)\s*="
    )
    allowed_runtime_writers = {STATUS.resolve(), (MESSENGER / "SharedConfig.java").resolve()}
    unexpected_writers: list[str] = []
    for path in JAVA_ROOT.rglob("*.java"):
        if path.resolve() in allowed_runtime_writers:
            continue
        source = read(path)
        if runtime_write_pattern.search(source):
            unexpected_writers.append(str(path.relative_to(ROOT)))
    if unexpected_writers:
        failures.append("Runtime ProxyInfo fields must be written only by ProxyStatusMirror compatibility mirror: " + ", ".join(unexpected_writers[:20]))

    if failures:
        print("Proxy control-plane policy guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Proxy control-plane policy guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
