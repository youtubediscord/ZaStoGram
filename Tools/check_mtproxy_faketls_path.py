#!/usr/bin/env python3
"""Static guard for the active MTProxy FakeTLS transport path.

The working reference is tsrman/tg commit 9fe18931 for the risky transport
parts: direct Firefox ClientHello, whole ClientHello send, blocking jitter, and
the original fixed TLS record cap for wrapped data.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
HDR = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"


def main() -> int:
    cpp = CPP.read_text(encoding="utf-8")
    header = HDR.read_text(encoding="utf-8")
    combined = cpp + "\n" + header
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(
        "TlsHello hello = TlsHello::getFirefoxDefault();" in cpp,
        "FakeTLS handshake must instantiate getFirefoxDefault() directly",
    )
    require(
        not re.search(r"\bTlsHello\s+TlsHello::pickProfile\s*\(", cpp),
        "FakeTLS profile wrapper must stay out of the active transport path",
    )
    require(
        "randomizeGrease" not in cpp and "randomizeGrease" not in header,
        "per-connection GREASE rewrite must stay disabled until server path is proven",
    )
    require(
        "send(socketFd, tempBuffer->bytes, size, 0)" in cpp,
        "ClientHello must be sent whole like the working tsrman path",
    )
    require(
        "remaining > 2878" in cpp,
        "wrapped data path must keep the original fixed TLS record cap",
    )
    require(
        "nextTlsRecordSize" not in combined
        and "tlsRecordRemaining" not in combined
        and "drs" not in combined.lower(),
        "dynamic record sizing must stay removed from the transport path",
    )
    require(
        "int delay = 500 + (rand() % 501);" in cpp,
        "proxy pacing must use the working tsrman blocking jitter",
    )
    require(
        "nanosleep(&ts, nullptr);" in cpp,
        "proxy pacing must block before connect like tsrman",
    )
    require(
        "pacingTimer" not in combined and "pacingDeferred" not in combined,
        "nonblocking Timer pacing must stay out of MTProxy connect",
    )
    require(
        '#include "Timer.h"' not in cpp,
        "ConnectionSocket.cpp must not depend on Timer for MTProxy pacing",
    )

    if errors:
        print("MTProxy FakeTLS path check failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("MTProxy FakeTLS path check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
