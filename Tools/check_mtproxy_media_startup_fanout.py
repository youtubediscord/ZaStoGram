#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
TOOLS = ROOT / "Tools"


def read(path):
    return path.read_text(encoding="utf-8")


def require(condition, message, failures):
    if not condition:
        failures.append(message)


def main():
    failures = []
    runtime = read(MESSENGER / "ProxyRuntimeStateStore.java")
    health = read(MESSENGER / "ProxyHealthStore.java")
    loader = read(MESSENGER / "FileLoader.java")
    queue = read(MESSENGER / "FileLoaderPriorityQueue.java")
    operation = read(MESSENGER / "FileLoadOperation.java")
    all_checks = read(TOOLS / "check_mtproxy_all.py")

    require(
        "lastUsableSuccessTime" in health
        and "lastUsableSuccessAgeMs" in health,
        "ProxyHealthStore must remember first usable MTProxy success beyond the short visible hold",
        failures,
    )
    require(
        "MEDIA_STARTUP_PRE_USABLE_REQUEST_LIMIT" in runtime
        and "MEDIA_STARTUP_RAMP_STEP_MS" in runtime
        and "fileLoaderStartupOperationLimit" in runtime
        and "fileLoaderStartupRequestLimit" in runtime,
        "ProxyRuntimeStateStore must expose startup media fanout limits with a gradual post-usable ramp",
        failures,
    )
    require(
        "isMtProxyStartupFanoutLimited" in runtime
        and "isMtProxyEnabledForStartupFanout" in runtime,
        "startup fanout limiting must be scoped to enabled MTProxy endpoints",
        failures,
    )
    require(
        "new FileLoaderPriorityQueue(instance, this," in loader
        and "canStartProxyStartupMediaOperation" in loader
        and "scheduleProxyStartupFanoutRecheck" in loader
        and "countProxyStartupActiveLoadOperations" in loader,
        "FileLoader must enforce an account-wide startup media operation gate across all DC queues",
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
        "ProxyRuntimeStateStore.fileLoaderStartupRequestLimit" in operation
        and "proxy_control decision=file_request_fanout_limited" in operation,
        "FileLoadOperation must cap the initial upload_getFile request window before/ramping after usable success",
        failures,
    )
    require(
        '"check_mtproxy_media_startup_fanout.py"' in all_checks,
        "full MTProxy guard suite must include the media startup fanout guard",
        failures,
    )

    if failures:
        print("MTProxy media startup fanout guard failed:")
        for failure in failures:
            print(f" - {failure}")
        raise SystemExit(1)
    print("MTProxy media startup fanout guard passed.")


if __name__ == "__main__":
    main()
