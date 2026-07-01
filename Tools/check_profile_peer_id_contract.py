#!/usr/bin/env python3
"""Static guard for always showing peer IDs on profile info screens."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java"
PROFILE_ACTIVITY2 = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity2.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
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
                return text[start:index + 1]
    return ""


def main() -> int:
    profile = read(PROFILE_ACTIVITY)
    profile2 = read(PROFILE_ACTIVITY2)
    strings = read(STRINGS)
    strings_ru = read(STRINGS_RU)
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require('<string name="PeerId">ID</string>' in strings, "Default strings must define PeerId")
    require('<string name="PeerIdCopied">ID copied to clipboard</string>' in strings, "Default strings must define PeerIdCopied")
    require('<string name="PeerId">ID</string>' in strings_ru, "Russian strings must define PeerId")
    require('<string name="PeerIdCopied">ID скопирован в буфер обмена</string>' in strings_ru, "Russian strings must define PeerIdCopied")

    update_rows = method_body(profile, "private void updateRowsIds()")
    bind_holder = method_body(profile, "public void onBindViewHolder(RecyclerView.ViewHolder holder, int position)")
    view_type = method_body(profile, "public int getItemViewType(int position)")

    require("private int peerIdRow;" in profile, "ProfileActivity must declare peerIdRow")
    require("peerIdRow = -1;" in update_rows, "ProfileActivity.updateRowsIds must reset peerIdRow")
    require(
        re.search(r"if \(user != null && username != null\)[\s\S]*?usernameRow = rowCount\+\+;[\s\S]*?peerIdRow = rowCount\+\+;", update_rows) is not None,
        "ProfileActivity user profiles must add peerIdRow after username handling, even when username is absent",
    )
    require(
        "peerIdRow = rowCount++;" in update_rows and "else if (chatId != 0)" in update_rows,
        "ProfileActivity chat profiles must add peerIdRow for groups, channels, and private chats",
    )
    require(
        "position == peerIdRow" in view_type and "VIEW_TYPE_TEXT_DETAIL" in view_type,
        "ProfileActivity must render peerIdRow as a TextDetailCell",
    )
    require(
        "position == peerIdRow" in bind_holder and "getPeerIdText()" in bind_holder and "R.string.PeerId" in bind_holder,
        "ProfileActivity must bind peerIdRow with the current peer ID",
    )
    require("private String getPeerIdText()" in profile, "ProfileActivity must centralize peer ID formatting")
    require("private boolean copyPeerId()" in profile and "R.string.PeerIdCopied" in profile, "ProfileActivity must copy peer ID from the info row")

    fill_items = method_body(profile2, "private void fillItems(ArrayList<UItem> items, UniversalAdapter adapter)")
    on_click = method_body(profile2, "private void onClick(UItem item, View view, int position, float x, float y)")

    require("private static final int ID_PEER_ID" in profile2, "ProfileActivity2 must define ID_PEER_ID")
    require("private void addPeerIdRow(ArrayList<UItem> items)" in profile2, "ProfileActivity2 must have addPeerIdRow")
    require(
        re.search(r"if \(user != null\)[\s\S]*?addUsernameRow\(items\);[\s\S]*?addPeerIdRow\(items\);", fill_items) is not None,
        "ProfileActivity2 user profiles must add peer ID after username",
    )
    require(
        re.search(r"else if \(chat != null\)[\s\S]*?addPeerIdRow\(items\);", fill_items) is not None,
        "ProfileActivity2 chat profiles must add peer ID for groups, channels, and private chats",
    )
    require(
        "TextDetailCell.Factory.of(ID_PEER_ID, getPeerIdText(), getString(R.string.PeerId))" in profile2,
        "ProfileActivity2 peer ID row must be a TextDetailCell",
    )
    require("private String getPeerIdText()" in profile2, "ProfileActivity2 must centralize peer ID formatting")
    require("private boolean copyPeerId()" in profile2, "ProfileActivity2 must copy peer ID from the info row")
    require("item.id == ID_PEER_ID" in on_click and "copyPeerId()" in on_click, "ProfileActivity2 must copy peer ID on row tap")

    if failures:
        print("Profile peer ID contract failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Profile peer ID contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
