#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MESSAGES_CONTROLLER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java"
CONNECTIONS_MANAGER = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def extract_update_timer_proc(text: str) -> str:
    marker = "public void updateTimerProc()"
    start = text.find(marker)
    if start < 0:
        return ""

    brace = text.find("{", start)
    if brace < 0:
        return ""

    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return ""


def main() -> int:
    failures: list[str] = []
    messages = read(MESSAGES_CONTROLLER)
    connections = read(CONNECTIONS_MANAGER)
    update_timer_proc = extract_update_timer_proc(messages)

    require(
        "private boolean canSendOnlinePresence()" in messages,
        "MessagesController must expose a single-account online-presence gate",
        failures,
    )
    require(
        re.search(
            r"private\s+boolean\s+canSendOnlinePresence\s*\(\s*\)\s*\{[^{}]*return\s+currentAccount\s*==\s*UserConfig\.selectedAccount\s*;",
            messages,
            re.DOTALL,
        )
        is not None,
        "online-presence gate must allow only UserConfig.selectedAccount",
        failures,
    )
    require(
        "boolean allowOnlinePresence = canSendOnlinePresence();" in update_timer_proc,
        "updateTimerProc() must compute the selected-account presence gate before status updates",
        failures,
    )
    require(
        re.search(
            r"if\s*\(\s*allowOnlinePresence\s*&&\s*!ignoreSetOnline\s*&&\s*getConnectionsManager\(\)\.getPauseTime\(\)\s*==\s*0",
            update_timer_proc,
            re.DOTALL,
        )
        is not None,
        "account.updateStatus(offline=false) must be reachable only through allowOnlinePresence",
        failures,
    )
    require(
        "} else if (statusSettingState != 2 && !offlineSent && (!allowOnlinePresence || Math.abs(System.currentTimeMillis() - getConnectionsManager().getPauseTime()) >= 2000)) {"
        in update_timer_proc,
        "non-selected accounts must still be able to send offline=true even when keepalive keeps pauseTime at zero",
        failures,
    )
    require(
        'BACKGROUND_NETWORK_ALWAYS_ON = "backgroundNetworkAlwaysOn"' in connections
        and "lastPauseTime = 0;" in connections
        and "native_resumeNetwork(currentAccount, false);" in connections,
        "background keepalive must remain transport-level and separate from online presence",
        failures,
    )

    if failures:
        print("Single active presence guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Single active presence guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
