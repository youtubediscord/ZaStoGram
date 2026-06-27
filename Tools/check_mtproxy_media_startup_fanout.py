#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
TOOLS = ROOT / "Tools"
RUNTIME_VERIFIER = TOOLS / "verify_mtproxy_runtime_logs.py"


def read(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def require(condition, message, failures):
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    brace = text.find("{", start)
    if brace == -1:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def runtime_log_base(pre_usable_lines: list[str], post_usable_lines: list[str] | None = None) -> str:
    lines = [
        "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
        "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196",
        "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
    ]
    lines.extend(pre_usable_lines)
    lines.extend(
        [
            "logcat.txt:40: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
            "logcat.txt:41: 06-25 20:31:30.100 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=sberbank.dns.army:45631 key=sberbank.dns.army:45631:ee:sberbank.dns.army reason=first_tls_app_recv",
            "logcat.txt:42: 06-25 20:31:30.110 proxy_control decision=visible_usable_success source=native_stage account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
        ]
    )
    if post_usable_lines:
        lines.extend(post_usable_lines)
    return "\n".join(lines) + "\n"


def run_runtime_log_checks(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bad_upload = tmp_path / "bad_upload.txt"
        bad_tcp_gate = tmp_path / "bad_tcp_gate.txt"
        bad_story = tmp_path / "bad_story.txt"
        bad_sticker = tmp_path / "bad_sticker.txt"
        good = tmp_path / "good.txt"
        bad_warmup_churn = tmp_path / "bad_warmup_churn.txt"
        bad_upload.write_text(
            runtime_log_base(
                [
                    f"logcat.txt:{10 + index}: 06-25 20:31:30.0{index}0 D/tmessages upload_getFile media_startup index={index}"
                    for index in range(4)
                ]
            ),
            encoding="utf-8",
        )
        bad_tcp_gate.write_text(
            runtime_log_base(
                [
                    f"logcat.txt:{10 + index}: 06-25 20:31:30.0{index}0 connection(0x{index + 2:x}) mtproxy_startup tcp_connect_gate active={index}"
                    for index in range(6)
                ]
            ),
            encoding="utf-8",
        )
        bad_story.write_text(
            runtime_log_base(
                [
                    "logcat.txt:10: 06-25 20:31:30.040 D/tmessages stories preload create load operation upload_getFile story_id=10",
                ]
            ),
            encoding="utf-8",
        )
        bad_sticker.write_text(
            runtime_log_base(
                [
                    "logcat.txt:10: 06-25 20:31:30.040 D/tmessages animated sticker create load operation upload_getFile sticker_id=10",
                ]
            ),
            encoding="utf-8",
        )
        good.write_text(
            runtime_log_base(
                [
                    "logcat.txt:10: 06-25 20:31:30.040 D/tmessages proxy_warmup state=cold decision=allow class=media_visible account=0 active=0 max=1",
                    "logcat.txt:11: 06-25 20:31:30.050 D/tmessages upload_getFile media_startup index=0",
                    "logcat.txt:12: 06-25 20:31:30.060 D/tmessages proxy_warmup bucket_delay class=stories_prefetch account=0 count=3 delay=1500",
                ],
                [
                    "logcat.txt:43: 06-25 20:31:30.400 D/tmessages proxy_warmup state=usable decision=ramp class=media_prefetch active=2 max=4",
                ],
            ),
            encoding="utf-8",
        )
        bad_warmup_churn.write_text(
            runtime_log_base(
                [
                    "logcat.txt:10: 06-25 20:31:30.040 D/tmessages proxy_warmup state=warming decision=delay class=stories_prefetch account=0 delay=1500 endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    "logcat.txt:11: 06-25 20:31:30.041 D/tmessages proxy_warmup state=warming decision=delay class=stories_prefetch account=0 delay=1500 endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    "logcat.txt:12: 06-25 20:31:30.042 D/tmessages proxy_warmup state=warming decision=delay class=sticker_prefetch account=0 delay=1500 endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    "logcat.txt:13: 06-25 20:31:30.043 D/tmessages proxy_warmup state=warming decision=delay class=sticker_prefetch account=0 delay=1500 endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                ]
            ),
            encoding="utf-8",
        )

        cases = (
            (bad_upload, "startup fanout before first usable success"),
            (bad_tcp_gate, "tcp_connect_gate before first usable success"),
            (bad_story, "stories preload must not create network file requests before usable success"),
            (bad_sticker, "sticker preload must not create network file requests before usable success"),
            (bad_warmup_churn, "proxy_warmup prefetch delays must be bucketed"),
        )
        for path, expected in cases:
            result = subprocess.run([sys.executable, str(RUNTIME_VERIFIER), str(path)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            require(
                result.returncode != 0 and expected in result.stderr,
                f"runtime verifier must reject {expected}",
                failures,
            )

        good_result = subprocess.run([sys.executable, str(RUNTIME_VERIFIER), str(good)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(
            good_result.returncode == 0,
            good_result.stderr.strip() or "runtime verifier must accept throttled warmup fanout",
            failures,
        )


def main():
    failures = []
    runtime = read(MESSENGER / "ProxyRuntimeStateStore.java")
    health = read(MESSENGER / "ProxyHealthStore.java")
    warmup = read(MESSENGER / "ProxyWarmupGate.java")
    loader = read(MESSENGER / "FileLoader.java")
    queue = read(MESSENGER / "FileLoaderPriorityQueue.java")
    operation = read(MESSENGER / "FileLoadOperation.java")
    media = read(MESSENGER / "MediaDataController.java")
    stories = read(ROOT / "TMessagesProj/src/main/java/org/telegram/ui/Stories/StoriesController.java")
    all_checks = read(TOOLS / "check_mtproxy_all.py")
    verifier = read(RUNTIME_VERIFIER)
    loader_delay = method_body(loader, "private boolean maybeDelayProxyStartupLoadFile")
    media_delay = method_body(media, "private boolean delayProxyWarmupPrefetch")
    stories_delay = method_body(stories, "private boolean delayProxyWarmupPrefetch")
    mark_usable = method_body(runtime, "public static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic, long now)")
    mark_failure = method_body(runtime, "public static ProxyHealthStore.EndpointFailureResult markEndpointFailure")

    require(
        "lastUsableSuccessTime" in health
        and "lastUsableSuccessAgeMs" in health,
        "ProxyHealthStore must remember first usable MTProxy success beyond the short visible hold",
        failures,
    )
    require(
        "public final class ProxyWarmupGate" in warmup
        and "public enum ProxyWarmupState" in warmup
        and "COLD" in warmup
        and "WARMING" in warmup
        and "USABLE" in warmup
        and "DEGRADED" in warmup,
        "startup media fanout must use a shared ProxyWarmupGate with explicit COLD/WARMING/USABLE/DEGRADED state",
        failures,
    )
    for request_class in (
        "INIT_CRITICAL",
        "USER_VISIBLE",
        "MEDIA_VISIBLE",
        "MEDIA_PREFETCH",
        "STORIES_PREFETCH",
        "STICKER_PREFETCH",
        "CONTACTS_SYNC",
        "BACKGROUND_REFRESH",
    ):
        require(request_class in warmup, f"ProxyWarmupGate must classify {request_class} requests", failures)
    require(
        "canStartNetworkHeavyOperation" in warmup
        and "delayForNetworkHeavyOperation" in warmup
        and "onProxyUsable" in warmup
        and "onProxyFailure" in warmup
        and "maxActiveMediaRequestsPerEndpoint" in warmup
        and "maxUploadGetFileOffsetsPerFile" in warmup,
        "ProxyWarmupGate must expose allow/delay/success/failure and media fanout limit APIs",
        failures,
    )
    require(
        "PRE_USABLE_MEDIA_LIMIT = 1" in warmup
        and "PRE_USABLE_PREFETCH_LIMIT = 0" in warmup
        and "USABLE_RAMP_STEP_MS = 400" in warmup
        and "USABLE_RAMP_INITIAL_LIMIT = 2" in warmup
        and "USABLE_RAMP_SECOND_LIMIT = 4" in warmup
        and "USABLE_RAMP_STABLE_MS = 5000" in warmup,
        "ProxyWarmupGate must encode the requested pre-usable and post-usable ramp limits",
        failures,
    )
    require(
        '"proxy_warmup state=' in warmup
        and "decision=delay" in warmup
        and "decision=allow" in warmup
        and "decision=release_delayed" in warmup
        and "decision=ramp" in warmup,
        "ProxyWarmupGate must log explicit proxy_warmup allow/delay/release/ramp decisions",
        failures,
    )
    require(
        "DelayedBucket" in warmup
        and "DelayedOperationScheduler" in warmup
        and "delayedBuckets" in warmup
        and "delayNetworkHeavyOperationIfNeeded" in warmup
        and "bucket_delay" in warmup,
        "ProxyWarmupGate must coalesce delayed prefetch operations into account/class/endpoint buckets and log bucket_delay",
        failures,
    )
    for body, owner in (
        (loader_delay, "FileLoader"),
        (media_delay, "MediaDataController"),
        (stories_delay, "StoriesController"),
    ):
        require(
            "ProxyWarmupGate.delayNetworkHeavyOperationIfNeeded" in body
            and "delayForNetworkHeavyOperation" not in body,
            f"{owner} must enqueue proxy warmup prefetch delays through the coalesced bucket API",
            failures,
        )
    require(
        "ProxyWarmupGate.onProxyUsable" in mark_usable
        and "ProxyEndpointKey.liveStage(proxyInfo)" in mark_usable,
        "usable MTProxy proof must switch ProxyWarmupGate to USABLE for the live endpoint",
        failures,
    )
    require(
        "ProxyWarmupGate.onProxyFailure" in mark_failure
        and "ProxyPhasePolicy.isPunitiveFailure" in mark_failure,
        "punitive endpoint failures must notify ProxyWarmupGate without using local/live phases",
        failures,
    )
    require(
        "new FileLoaderPriorityQueue(instance, this," in loader
        and "canStartProxyStartupMediaOperation" in loader
        and "maybeDelayProxyStartupLoadFile" in loader
        and "classifyProxyWarmupRequest" in loader
        and "scheduleProxyStartupFanoutRecheck" in loader
        and "countProxyStartupActiveLoadOperations" in loader
        and "ProxyWarmupGate.canStartNetworkHeavyOperation" in loader
        and "ProxyWarmupGate.maxActiveMediaRequestsPerEndpoint" in loader
        and "ProxyWarmupGate.delayForNetworkHeavyOperation" in loader,
        "FileLoader must delay prefetch operation creation and enforce an account-wide startup media operation gate across all DC queues through ProxyWarmupGate",
        failures,
    )
    require(
        "ProxyWarmupGate.NetworkRequestClass.STORIES_PREFETCH" in loader
        and "ProxyWarmupGate.NetworkRequestClass.STICKER_PREFETCH" in loader
        and "ProxyWarmupGate.NetworkRequestClass.MEDIA_PREFETCH" in loader
        and "ProxyWarmupGate.NetworkRequestClass.MEDIA_VISIBLE" in loader,
        "FileLoader must classify stories, stickers, media prefetch, and visible media before creating load operations",
        failures,
    )
    require(
        "private final FileLoader startupGate;" in queue
        and "startupGate.canStartProxyStartupMediaOperation" in queue
        and "startupGate.scheduleProxyStartupFanoutRecheck" in queue,
        "FileLoaderPriorityQueue must consult the account-wide startup gate before starting operations",
        failures,
    )
    require(
        "proxyWarmupRequestClass" in operation
        and "ProxyWarmupGate.NetworkRequestClass.STORIES_PREFETCH" in operation
        and "ProxyWarmupGate.NetworkRequestClass.MEDIA_PREFETCH" in operation
        and "ProxyWarmupGate.NetworkRequestClass.STICKER_PREFETCH" in operation
        and "ProxyWarmupGate.NetworkRequestClass.MEDIA_VISIBLE" in operation
        and "ProxyWarmupGate.maxUploadGetFileOffsetsPerFile" in operation
        and "proxy_warmup state=" in operation,
        "FileLoadOperation must classify media/story/sticker/preload requests and cap upload_getFile offsets through ProxyWarmupGate",
        failures,
    )
    require(
        "verify_startup_warmup_fanout" in verifier
        and "count(upload_getFile) > 3" in verifier
        and "count(tcp_connect_gate) > 5" in verifier
        and "stories preload must not create network file requests before usable success" in verifier,
        "runtime verifier must enforce startup fanout acceptance criteria before first usable success",
        failures,
    )
    require(
        "sticker preload must not create network file requests before usable success" in verifier
        and "proxy_warmup state=usable decision=ramp" in verifier,
        "runtime verifier must reject sticker prefetch creation before usable and require ramp to happen after usable",
        failures,
    )
    require(
        "delayProxyWarmupPrefetch" in media
        and "ProxyWarmupGate.NetworkRequestClass.STICKER_PREFETCH" in media
        and "preloadPremiumPreviewStickers" in media,
        "MediaDataController must delay sticker/reaction preview prefetch until MTProxy warmup allows it",
        failures,
    )
    require(
        "delayProxyWarmupPrefetch" in stories
        and "ProxyWarmupGate.NetworkRequestClass.STORIES_PREFETCH" in stories
        and "preloadStory" in stories,
        "StoriesController must delay story preload file requests until MTProxy warmup allows them",
        failures,
    )
    require(
        '"check_mtproxy_media_startup_fanout.py"' in all_checks,
        "full MTProxy guard suite must include the media startup fanout guard",
        failures,
    )
    run_runtime_log_checks(failures)

    if failures:
        print("MTProxy media startup fanout guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("MTProxy media startup fanout guard passed.")


if __name__ == "__main__":
    main()
