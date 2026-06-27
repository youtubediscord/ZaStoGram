#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
JAVA_CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
TLRPC = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java"
MTPROXY_ALL = ROOT / "Tools/check_mtproxy_all.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    failures: list[str] = []
    connections = read(CONNECTIONS)
    java_connections = read(JAVA_CONNECTIONS)
    tlrpc = read(TLRPC)
    mtproxy_all = read(MTPROXY_ALL)

    require(
        "not found request to parse constructor" not in connections
        and "received unparsed packet" not in connections
        and "not found file" not in connections,
        "debug parser schema gaps must not use failure-looking not-found/unparsed-packet wording",
        failures,
    )
    require(
        "debug_parser_unmapped constructor=0x%x" in connections,
        "unmapped TL constructors must be logged with neutral debug_parser_unmapped wording",
        failures,
    )
    require(
        "debug_parser_unmapped_packet req_msg_id=0x%" in connections,
        "packets delegated to the Java parser must be logged as debug-parser unmapped packets",
        failures,
    )
    require(
        "java received unknown constructor" not in java_connections
        and "java_debug_parser_unmapped constructor=0x%x" in java_connections,
        "Java parser fallback must use neutral java_debug_parser_unmapped wording for unmapped constructors",
        failures,
    )
    require(
        "constructor == 0x96a18d5" not in connections,
        "ConnectionsManager must not special-case upload.File as a fake not-found condition",
        failures,
    )
    require(
        "case 0x96a18d5:" in tlrpc
        and "TL_upload_file" in tlrpc
        and "case 0x78d4dec1:" in tlrpc
        and "TL_updateShort" in tlrpc,
        "Java TL schema must already know the repeated upload.File/updateShort constructors that native debug parser may skip",
        failures,
    )
    require(
        '"check_debug_parser_unmapped_logs.py"' in mtproxy_all,
        "full MTProxy guard suite must include debug-parser unmapped log guard",
        failures,
    )

    if failures:
        print("Debug parser unmapped log guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Debug parser unmapped log guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
