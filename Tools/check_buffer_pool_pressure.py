#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
BUFFERS_CPP = ROOT / "TMessagesProj/jni/tgnet/BuffersStorage.cpp"
BUFFERS_H = ROOT / "TMessagesProj/jni/tgnet/BuffersStorage.h"
MTPROXY_ALL = ROOT / "Tools/check_mtproxy_all.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    failures: list[str] = []
    buffers_cpp = read(BUFFERS_CPP)
    buffers_h = read(BUFFERS_H)
    mtproxy_all = read(MTPROXY_ALL)

    require(
        "too much %d buffers" not in buffers_cpp,
        "buffer pool pressure must not use failure-looking 'too much buffers' wording",
        failures,
    )
    require(
        "buffer_pool_pressure capacity=%u cached=%u limit=%u" in buffers_cpp,
        "buffer pool pressure must log neutral capacity/cached/limit counters",
        failures,
    )
    require(
        "BUFFER_POOL_PRESSURE_LOG_INTERVAL_MS" in buffers_cpp
        and re.search(r"BUFFER_POOL_PRESSURE_LOG_INTERVAL_MS\s*=\s*1000", buffers_cpp),
        "buffer pool pressure log must be throttled to a once-per-second interval",
        failures,
    )
    require(
        "lastPressureLogByCapacity" in buffers_h
        and "lastPressureLogByCapacity[capacity]" in buffers_cpp,
        "buffer pool pressure throttling must be tracked per capacity",
        failures,
    )
    require(
        "bufferPoolMaxCountForCapacity" in buffers_cpp
        and "capacity == 1024 + 200" in buffers_cpp
        and re.search(r"capacity\s*==\s*1024\s*\+\s*200[^;{]*\{[^}]*return\s+80\s*;", buffers_cpp, re.S),
        "1224-byte buffers used by TLS frame assembly must get the hot-buffer cache cap, not the generic cap of 10",
        failures,
    )
    require(
        '"check_buffer_pool_pressure.py"' in mtproxy_all,
        "full guard suite must include buffer-pool pressure guard",
        failures,
    )

    if failures:
        print("Buffer pool pressure guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Buffer pool pressure guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
