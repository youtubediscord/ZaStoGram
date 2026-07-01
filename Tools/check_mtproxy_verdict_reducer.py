#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
TGNET_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
TGNET = ROOT / "TMessagesProj/jni/tgnet"
JNI = ROOT / "TMessagesProj/jni"
VALUES = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
VALUES_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        return ""
    brace = source.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    return ""


def string_has_case(source: str, method: str, constant: str, resource: str) -> bool:
    body = method_body(source, method)
    case = f"case {constant}:"
    case_index = body.find(case)
    if case_index < 0:
        return False
    next_case = body.find("case ", case_index + len(case))
    section = body[case_index: next_case if next_case >= 0 else len(body)]
    return resource in section


def main() -> int:
    failures: list[str] = []
    diagnostics = read(MESSENGER / "ProxyCheckDiagnostics.java")
    phase_policy = read(MESSENGER / "ProxyPhasePolicy.java")
    verdict = read(MESSENGER / "ProxyEndpointVerdict.java")
    visible = read(MESSENGER / "ProxyVisibleStateStore.java")
    health = read(MESSENGER / "ProxyHealthStore.java")
    runtime = read(MESSENGER / "ProxyRuntimeStateStore.java")
    reducer = read(MESSENGER / "ProxyEventReducer.java")
    event = read(MESSENGER / "ProxyConnectionEvent.java")
    java_connections = read(TGNET_JAVA)
    proxy_scheduler = read(MESSENGER / "ProxyCheckScheduler.java")
    shared_config = read(MESSENGER / "SharedConfig.java")
    status_mirror = read(MESSENGER / "ProxyStatusMirror.java")
    proxy_list = read(ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java")
    proxy_settings = read(ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProxySettingsActivity.java")
    android_utilities = read(MESSENGER / "AndroidUtilities.java")
    connection_socket_h = read(TGNET / "ConnectionSocket.h")
    connection_socket_cpp = read(TGNET / "ConnectionSocket.cpp")
    startup_timeline = read(TGNET / "MtProxyStartupTimeline.cpp")
    manager_h = read(TGNET / "ConnectionsManager.h")
    manager_cpp = read(TGNET / "ConnectionsManager.cpp")
    defines_h = read(TGNET / "Defines.h")
    wrapper = read(JNI / "TgNetWrapper.cpp")
    values = read(VALUES)
    values_ru = read(VALUES_RU)
    reducer_body = method_body(reducer, "static ProxyRuntimeStateStore.Decision reduce")

    for field in ("layer", "failureClass", "confidence", "action", "userTextKey", "endpointKey", "networkKey"):
        require(f"final String {field}" in verdict, f"ProxyEndpointVerdict must expose {field}", failures)
    require("final long stickyUntilMs" in verdict, "ProxyEndpointVerdict must expose stickyUntilMs", failures)
    require("final int activationGeneration" in verdict, "ProxyEndpointVerdict must expose activationGeneration", failures)
    require("final ProxyConnectionEvent.Origin origin" in verdict, "ProxyEndpointVerdict must expose origin", failures)
    for layer in (
        "scheduler_local",
        "dns",
        "tcp",
        "mtproxy_plain",
        "faketls_handshake",
        "post_handshake_data",
        "lifecycle_cancelled",
    ):
        require(f'"{layer}"' in verdict, f"ProxyEndpointVerdict layer taxonomy must include {layer}", failures)
    for old_layer in ('"local"', '"faketls"', '"mtproto"', '"config"', '"lifecycle"'):
        require(old_layer not in verdict and old_layer not in phase_policy, f"verdict layer taxonomy must not use old layer {old_layer}", failures)
    for failure_class in (
        "tcp_refused",
        "tcp_timeout",
        "tcp_gate_wait_timeout",
        "dns_failed",
        "mtproxy_no_response_after_send",
        "post_success_data_path_degraded",
        "faketls_no_server_hello",
        "faketls_bad_server_flight",
        "secret_invalid",
        "probe_wait_timeout",
        "stale_generation_cancelled",
    ):
        require(f'"{failure_class}"' in verdict or f'"{failure_class}"' in phase_policy, f"failureClass taxonomy must include {failure_class}", failures)
    for old_class in (
        "pre_tcp_local_wait",
        "dns_failure",
        "tcp_failure",
        "no_bytes_after_client_hello",
        "server_bytes_parser_failure",
        "server_hello_hmac_mismatch",
        "post_handshake_no_app_data",
        "config_invalid_secret",
        "cancelled_or_shadowed",
    ):
        require(old_class not in verdict and old_class not in phase_policy, f"failureClass taxonomy must not use old evidence bucket {old_class}", failures)
    require(
        "public static ProxyEndpointVerdict verdictForPhase" in phase_policy
        and "layerForPhase" in phase_policy
        and "failureClassForPhase" in phase_policy
        and "verdictForEvent" in phase_policy
        and "userTextKeyForFailureClass" in phase_policy
        and "freshFailureHoldEarlyRetryMs()" in phase_policy,
        "ProxyPhasePolicy must build a unified ProxyEndpointVerdict with identity/layer/failure/action/text/sticky data",
        failures,
    )
    require(
        "ProxyPhasePolicy.verdictForPhase(diagnostic, 0)" in diagnostics
        and "diagnosticResourceId(verdict.userTextKey)" in diagnostics,
        "diagnostic UI text must resolve through ProxyEndpointVerdict.userTextKey",
        failures,
    )
    require(
        "userTextKeyForFailureClass" in phase_policy
        and "FAILURE_CLASS_TCP_REFUSED" in phase_policy
        and "ProxyStatusTcpConnectionRefused" in phase_policy
        and "FAILURE_CLASS_MTPROXY_NO_RESPONSE_AFTER_SEND" in phase_policy
        and "ProxyStatusMtproxyPacketSentNoResponse" in phase_policy
        and "FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED" in phase_policy
        and "ProxyStatusDroppedAfterAppData" in phase_policy,
        "failure UI text must be selected from failureClass taxonomy, not only raw phase strings",
        failures,
    )
    failure_text = method_body(phase_policy, "static String userTextKeyForFailureClass")
    require(
        "FAILURE_CLASS_FAKETLS_NO_SERVER_HELLO" in failure_text
        and "FAKETLS_SERVER_HELLO_WAIT_TIMEOUT" in failure_text
        and "SERVER_CLOSED_AFTER_CLIENT_HELLO" in failure_text
        and "return userTextKeyForPhase(phase)" in failure_text,
        "faketls no-server-hello failureClass must preserve phase-specific UI keys for timeout and server-close phases",
        failures,
    )

    missing_map = {
        "MTPROXY_PROBE_WAIT": "ProxyStatusMtproxyProbeWait",
        "MTPROXY_PROBE_WAIT_TIMEOUT": "ProxyStatusMtproxyProbeWaitTimeout",
        "FAKETLS_SERVER_HELLO_WAIT_TIMEOUT": "ProxyStatusFaketlsServerHelloWaitTimeout",
        "SERVER_CLOSED_AFTER_CLIENT_HELLO": "ProxyStatusServerClosedAfterClientHello",
        "BACKGROUND_HANDSHAKE_ABORTED": "ProxyStatusBackgroundHandshakeAborted",
        "TCP_CONNECTION_REFUSED": "ProxyStatusTcpConnectionRefused",
        "TCP_CONNECT_TIMEOUT": "ProxyStatusTcpConnectTimeout",
    }
    for constant, resource in missing_map.items():
        require(resource in values, f"English strings must define {resource}", failures)
        require(resource in values_ru, f"Russian strings must define {resource}", failures)
        require(
            string_has_case(diagnostics, "private static HeaderStatusTitle diagnosticTitle", constant, f"R.string.{resource}"),
            f"diagnosticTitle must map {constant} to {resource}",
            failures,
        )
        require(
            string_has_case(diagnostics, "public static String diagnosticText", constant, f"R.string.{resource}"),
            f"diagnosticText must map {constant} to {resource}",
            failures,
        )

    keep_failure = method_body(diagnostics, "private static boolean shouldKeepFreshFailure")
    weak_method = method_body(diagnostics, "public static boolean isWeakRetryLivePhase")
    for constant in (
        "MTPROXY_PROBE_WAIT",
        "TCP_CONNECT_GATE",
        "DNS_CACHE_HIT",
        "ENDPOINT_COOLDOWN",
        "CONNECT_START",
    ):
        require(
            f"case {constant}:" in weak_method or f"case ProxyCheckDiagnostics.{constant}:" in weak_method,
            f"fresh failure sticky window must treat {constant} as weak retry/live telemetry",
            failures,
        )
    require(
        "isWeakRetryLivePhase(incomingDiagnostic)" in keep_failure,
        "fresh failure hold must use the weak retry/live phase classifier",
        failures,
    )
    require(
        "shouldKeepFreshFailure(SharedConfig.ProxyInfo proxyInfo, String incomingDiagnostic, int incomingActivationGeneration)" in diagnostics
        and "incomingActivationGeneration == proxyInfo.lastCheckActivationGeneration" in diagnostics
        and "ProxyCheckDiagnostics.shouldKeepFreshFailure(proxyInfo, event.phase, event.activationGeneration)" in visible,
        "fresh failure sticky hold must be bound to the visible failure activation generation",
        failures,
    )
    require(
        "int lastCheckActivationGeneration" in shared_config
        and "mirrorVisiblePhase(SharedConfig.ProxyInfo proxyInfo, String phase, long now, int activationGeneration)" in status_mirror
        and "proxyInfo.lastCheckActivationGeneration = activationGeneration" in status_mirror
        and "ProxyStatusMirror.mirrorVisiblePhase(proxyInfo, visiblePhase, event.timestamp, event.activationGeneration)" in visible
        and "ProxyRuntimeStateStore.markConnectionUsable(currentProxy, event.phase, event.timestamp, event.activationGeneration)" in reducer_body,
        "visible diagnostic state must record the activationGeneration from native socket verdict events",
        failures,
    )
    policy_punitive = method_body(phase_policy, "public static boolean isPunitiveFailure")
    policy_failure_class = method_body(phase_policy, "public static String failureClassForPhase")
    policy_classify = method_body(phase_policy, "private static PhaseInfo classify")
    required_failure_classes = {
        "TCP_CONNECTION_REFUSED": "FAILURE_CLASS_TCP_REFUSED",
        "TCP_CONNECT_TIMEOUT": "FAILURE_CLASS_TCP_TIMEOUT",
        "TCP_CONNECT_GATE_TIMEOUT": "FAILURE_CLASS_TCP_GATE_WAIT_TIMEOUT",
        "MTPROXY_PROBE_WAIT_TIMEOUT": "FAILURE_CLASS_PROBE_WAIT_TIMEOUT",
        "MTPROXY_PACKET_SENT_NO_RESPONSE": "FAILURE_CLASS_MTPROXY_NO_RESPONSE_AFTER_SEND",
        "DROPPED_AFTER_APPDATA": "FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED",
        "SECRET_PARSE_INVALID_DOMAIN": "FAILURE_CLASS_SECRET_INVALID",
        "IGNORED_CANCELLED_GENERATION": "FAILURE_CLASS_STALE_GENERATION_CANCELLED",
    }
    for constant, failure_class in required_failure_classes.items():
        require(
            f"case ProxyCheckDiagnostics.{constant}:" in policy_failure_class
            and failure_class in policy_failure_class[policy_failure_class.find(f"case ProxyCheckDiagnostics.{constant}:"):],
            f"{constant} must map to {failure_class}",
            failures,
        )
    for constant in ("TCP_CONNECTION_REFUSED", "TCP_CONNECT_TIMEOUT"):
        require(
            f"case ProxyCheckDiagnostics.{constant}:" in policy_punitive
            and f"case ProxyCheckDiagnostics.{constant}:" in policy_classify
            and f"case ProxyCheckDiagnostics.{constant}:" in policy_failure_class,
            f"{constant} must be a punitive network TCP failure with exact failureClass",
            failures,
        )

    require(
        "ProxyEndpointVerdict verdict = ProxyPhasePolicy.verdictForEvent(event)" in reducer_body
        and "verdict.failureClass" in reducer_body
        and "failure_class=" in reducer_body
        and "verdict.stickyUntilMs" in reducer_body
        and "new ProxyRuntimeStateStore.Decision(\"backoff\", verdict.phase" in reducer_body,
        "reducer must use ProxyEndpointVerdict as the visible/backoff decision contract, not a decorative object",
        failures,
    )
    require(
        "ProxyPhasePolicy.postSuccessDataPathVerdict(verdict)" in reducer_body
        and "FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED" in phase_policy,
        "reducer must upgrade post-success no-response failures to post_success_data_path_degraded",
        failures,
    )
    require(
        "visiblePhaseForVerdict(verdict)" in reducer_body
        and "ProxyEndpointVerdict.FAILURE_CLASS_POST_SUCCESS_DATA_PATH_DEGRADED.equals(verdict.failureClass)" in reducer
        and "ProxyCheckDiagnostics.DROPPED_AFTER_APPDATA" in reducer,
        "post-success degraded verdict must write a visible diagnostic that resolves to the degraded data-path UI text",
        failures,
    )
    visible_write = reducer_body.find("ProxyVisibleStateStore.mirrorVisiblePhaseIfAllowed")
    stale_generation = reducer_body.find("ProxyRuntimeStateStore.shouldIgnoreStaleActivationGeneration(event)")
    coalesce_probe = reducer_body.find("ProxyVisibleStateStore.shouldCoalesceProbeWait(currentProxy, event)")
    fresh_failure_hold = reducer_body.find("ProxyVisibleStateStore.shouldHoldVisiblePhaseByFreshFailure(currentProxy, event)")
    require(
        stale_generation >= 0 and stale_generation < reducer_body.find("ProxyWarmupGate.onProxyLivePhase"),
        "reducer must ignore stale activation generations before live/failure state changes",
        failures,
    )
    require(
        fresh_failure_hold >= 0 and coalesce_probe >= 0 and visible_write >= 0 and fresh_failure_hold < coalesce_probe < visible_write,
        "probe-wait coalescing must run after sticky failure hold and before visible writes",
        failures,
    )
    require(
        'return new ProxyRuntimeStateStore.Decision("telemetry_only"' in reducer_body[coalesce_probe:visible_write],
        "coalesced probe-wait joiners must become telemetry-only decisions",
        failures,
    )
    require(
        "PROBE_WAIT_VISIBLE_REPEAT_MS" in visible
        and "lastVisibleProbeWaitEndpointKey" in visible
        and "lastVisibleProbeWaitProbeKey" in visible
        and "lastVisibleProbeWaitActivationGeneration" in visible
        and "event.activationGeneration == lastVisibleProbeWaitActivationGeneration" in visible
        and "resetProbeWaitCoalescing" in visible,
        "visible state store must coalesce repeated mtproxy_probe_wait per endpoint/probe/generation",
        failures,
    )

    require("activationGeneration" in event and "final int activationGeneration" in event, "ProxyConnectionEvent must carry activationGeneration", failures)
    require("final String networkKey" in event and "ProxyEndpointKey.networkFromLiveStage" in event, "ProxyConnectionEvent must carry/derive networkKey", failures)
    require("ACTIVE_SOCKET(\"active_socket\")" in event and "ACTIVE_PROXY" not in event, "ProxyConnectionEvent must expose active_socket, not active_proxy, as the active origin", failures)
    require("USER_SELECT(\"user_select\")" in event and "ROTATION_CANDIDATE(\"rotation_candidate\")" in event, "ProxyConnectionEvent origins must include user_select and rotation_candidate causes", failures)
    require(
        "isActiveProxyOrigin" in event
        and "case USER_SELECT:" in event
        and "case STARTUP_RESTORE:" in event
        and "case BACKGROUND_KEEPALIVE:" in event
        and "ProxyConnectionEvent.isActiveProxyOrigin(event.origin)" in runtime
        and "ProxyConnectionEvent.isActiveProxyOrigin(event.origin)" in read(MESSENGER / "ProxyEventReducer.java"),
        "active-socket activation origins must still route through active visible/backoff reducer paths",
        failures,
    )
    require(
        "noteProxySettingsActivation(ProxyConnectionEvent.Origin origin)" in runtime
        and "noteProxyStartupRestoreActivation(int account)" in runtime
        and "noteProxyLifecycleActivation(int account, ProxyConnectionEvent.Origin origin)" in runtime
        and "shouldIgnoreStaleActivationGeneration" in runtime,
        "runtime store must own settings/startup/background activation generation floors",
        failures,
    )
    stale_generation_method = method_body(runtime, "static boolean shouldIgnoreStaleActivationGeneration")
    require(
        "event.activationGeneration <= 0" not in stale_generation_method
        and "event.activationGeneration != floor" in stale_generation_method,
        "activation generation gate must drop any active socket event whose generation differs from the current account generation",
        failures,
    )
    require("proxyActivationGeneration" in manager_h and "getProxyActivationGeneration" in manager_h and "proxyActivationOrigin" in manager_h and "getProxyActivationOrigin" in manager_h, "native ConnectionsManager must own proxy activation generation and origin", failures)
    require(
        "uint32_t activationGeneration" in manager_h
        and "uint32_t activationGeneration" in manager_cpp
        and "proxyActivationGeneration = activationGeneration" in manager_cpp
        and "proxyActivationOrigin = activationOrigin.empty() ? \"active_socket\" : activationOrigin" in manager_cpp
        and "setProxyActivationContext" in manager_h
        and "setProxyActivationContext" in manager_cpp
        and "getProxyActivationGeneration()" in manager_cpp
        and "getProxyActivationOrigin()" in manager_cpp,
        "native setProxySettings/resume context must accept the Java activation generation and active_socket origin instead of counting independently",
        failures,
    )
    require(
        "proxyActivationGeneration = manager.getProxyActivationGeneration()" in connection_socket_cpp
        and "proxyActivationOrigin = manager.getProxyActivationOrigin()" in connection_socket_cpp
        and "origin == \"active_socket\"" in connection_socket_cpp
        and "proxyActivationOrigin" in connection_socket_cpp,
        "ConnectionSocket must capture activation generation/origin at open and only override ordinary active_socket origin",
        failures,
    )
    require("proxyActivationGeneration" in connection_socket_h and "proxyActivationOrigin" in connection_socket_h, "ConnectionSocket must store captured activation generation and origin", failures)
    require("onProxyConnectionStageChanged(int32_t instanceNum, std::string diagnostic, std::string endpointKey, std::string probeKey, std::string origin, int32_t activationGeneration)" in defines_h, "native delegate must pass activationGeneration", failures)
    require("CallStaticVoidMethod" in wrapper and "activationGeneration" in wrapper and "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V" in wrapper, "JNI stage wrapper must forward activationGeneration to Java", failures)
    require(
        "int activationGeneration = ProxyRuntimeStateStore.noteProxyStartupRestoreActivation(currentAccount)" in java_connections
        and "ProxyConnectionEvent.Origin.STARTUP_RESTORE.wireName" in java_connections
        and "ProxyRuntimeStateStore.noteProxySettingsActivation(activationOrigin)" in java_connections
        and "native_setProxySettings(a, address, port, username, password, secret, enabledOptions, activationGeneration, activationOrigin.wireName)" in java_connections
        and "publishProxyActivationContext(ProxyConnectionEvent.Origin.BACKGROUND_KEEPALIVE)" in java_connections
        and "publishProxyActivationContext(ProxyConnectionEvent.Origin.ACTIVE_SOCKET)" in java_connections
        and "native_setProxyActivationContext(currentAccount, activationGeneration, activationOrigin.wireName)" in java_connections,
        "Java must pass settings/startup/background generation and origin to native",
        failures,
    )
    require(
        "jint activationGeneration" in wrapper
        and "jstring activationOrigin" in wrapper
        and "MtProxyOptions;ILjava/lang/String;)V" in wrapper
        and "native_setProxyActivationContext" in wrapper
        and "activationGeneration > 0 ? (uint32_t) activationGeneration : 0" in wrapper,
        "JNI native_setProxySettings/native_setProxyActivationContext must bridge activationGeneration and origin to native",
        failures,
    )
    require(
        "decision.diagnostic = \"tcp_connect_timeout\"" in startup_timeline
        and "return \"tcp_connect_timeout\"" in startup_timeline,
        "startup timeline must expose real TCP connect timeout as tcp_connect_timeout",
        failures,
    )
    require(
        "error == ECONNREFUSED" in connection_socket_cpp
        and "MtProxyPhase::TcpConnectionRefused" in connection_socket_cpp
        and "error == ETIMEDOUT" in connection_socket_cpp
        and "MtProxyPhase::TcpConnectTimeout" in connection_socket_cpp
        and "reason == 2" in connection_socket_cpp,
        "native terminal diagnostic must split ECONNREFUSED and TCP timeout before generic tcp_not_connected",
        failures,
    )
    analyzer = read(ROOT / "Tools/analyze_mtproxy_markers.py")
    require(
        'return "tcp_connection_refused"' in analyzer
        and 'return "tcp_connect_timeout"' in analyzer,
        "analyzer verdicts must preserve split TCP refused/timeout failures",
        failures,
    )

    java_stage = method_body(java_connections, "public static void onProxyConnectionStageChanged(final int currentAccount, final String diagnostic, final String endpointKey, final String probeKey, final String origin, final int activationGeneration)")
    require(
        "ProxyRuntimeStateStore.Decision decision = ProxyRuntimeStateStore.onNativeStage(event)" in java_stage
        and "if (!shouldNotifyProxyConnectionStage(decision))" in java_stage
        and "return;" in java_stage[java_stage.find("if (!shouldNotifyProxyConnectionStage(decision))"):],
        "Java bridge must suppress UI notifications for telemetry-only reducer decisions",
        failures,
    )
    notify_method = method_body(java_connections, "private static boolean shouldNotifyProxyConnectionStage")
    require(
        "decision.visibleChanged" in notify_method and "decision.rotationTrigger" in notify_method,
        "notification gate must allow visible changes and rotation triggers",
        failures,
    )

    mark_start = method_body(visible, "static void markConnectionStarting")
    require(
        "origin == ProxyConnectionEvent.Origin.USER_SELECT" in mark_start
        and "origin == ProxyConnectionEvent.Origin.SETTINGS_CHANGE" in mark_start
        and "ProxyHealthStore.clearUsableSuccessHold(proxyInfo" in mark_start
        and "ProxyStatusMirror.markConnectionStarting(proxyInfo, now)" in mark_start,
        "explicit user/settings activation must force connect_start and clear stale usable-success hold",
        failures,
    )
    require(
        "ProxyCheckDiagnostics.shouldKeepFreshFailure(proxyInfo, ProxyCheckDiagnostics.CONNECT_START)" in mark_start
        and "decision=held_by_fresh_failure" in mark_start
        and mark_start.find("ProxyCheckDiagnostics.shouldKeepFreshFailure(proxyInfo, ProxyCheckDiagnostics.CONNECT_START)") < mark_start.rfind("ProxyStatusMirror.markConnectionStarting(proxyInfo, now)"),
        "routine Java connect_start must not overwrite a fresh terminal failure",
        failures,
    )
    require("clearUsableSuccessHold" in health, "ProxyHealthStore must expose explicit activation usable-success clearing", failures)
    require("markConnectionStarting(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent.Origin origin)" in runtime, "runtime store must accept markConnectionStarting origin", failures)
    require("markConnectionStarting(SharedConfig.ProxyInfo proxyInfo, ProxyConnectionEvent.Origin origin)" in proxy_scheduler, "scheduler facade must accept markConnectionStarting origin", failures)
    require("ProxyConnectionEvent.Origin.USER_SELECT" in proxy_list, "ProxyListActivity user selection must mark user_select activation", failures)
    require("ProxyConnectionEvent.Origin.SETTINGS_CHANGE" in proxy_settings, "ProxySettingsActivity apply must mark settings_change activation", failures)
    require("ProxyConnectionEvent.Origin.USER_SELECT" in android_utilities, "proxy link apply must mark user_select activation", failures)
    require("ProxyConnectionEvent.Origin.ROTATION_CANDIDATE" in read(MESSENGER / "ProxyRotationController.java"), "rotation controller must mark rotation_candidate activation", failures)

    require(
        "POST_SUCCESS_DATA_PATH_SHADOWS = 1" in health
        and "POST_SUCCESS_DATA_PATH_SHADOWS = 1" in connection_socket_cpp + manager_cpp + read(TGNET / "MtProxyEndpointPolicy.cpp")
        and "postSuccessDataPathShadowCount >= POST_SUCCESS_DATA_PATH_SHADOWS" in health
        and "postSuccessDataPathShadowCount >= MT_PROXY_ENDPOINT_POST_SUCCESS_DATA_PATH_SHADOWS" in read(TGNET / "MtProxyEndpointPolicy.cpp"),
        "post-success data-path shadow budget must stay bounded to one in Java and native",
        failures,
    )

    if failures:
        print("MTProxy verdict reducer guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    print("MTProxy verdict reducer guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
