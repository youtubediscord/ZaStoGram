#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTION = ROOT / "TMessagesProj/jni/tgnet/Connection.cpp"
MTPROXY_ALL = ROOT / "Tools/check_mtproxy_all.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    failures: list[str] = []
    connection = read(CONNECTION)
    mtproxy_all = read(MTPROXY_ALL)

    require(
        "received packet size less" not in connection
        and "then message size" not in connection,
        "partial MTProto packet assembly must not use failure-looking packet-size wording",
        failures,
    )
    require(
        "mtproto_partial_packet need=%u got=%u" in connection,
        "partial MTProto packet assembly must log neutral need/got counters",
        failures,
    )
    partial_idx = connection.find("mtproto_partial_packet need=%u got=%u")
    store_idx = connection.find("restOfTheData = BuffersStorage::getInstance().getFreeBuffer(len)", partial_idx)
    require(
        partial_idx >= 0
        and store_idx >= 0
        and partial_idx < store_idx,
        "partial MTProto packet log must describe the normal buffer assembly path before storing restOfTheData",
        failures,
    )
    require(
        '"check_mtproto_partial_packet_log.py"' in mtproxy_all,
        "full MTProxy guard suite must include MTProto partial-packet log guard",
        failures,
    )

    if failures:
        print("MTProto partial-packet log guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("MTProto partial-packet log guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
