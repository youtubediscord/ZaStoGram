#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"missing {label}: {needle}")


def main() -> None:
    shared = read("TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java")
    message_object = read("TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java")
    theme_activity = read("TMessagesProj/src/main/java/org/telegram/ui/ThemeActivity.java")
    chat_activity = read("TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java")
    chat_cell = read("TMessagesProj/src/main/java/org/telegram/ui/Cells/ChatMessageCell.java")
    photo_viewer = read("TMessagesProj/src/main/java/org/telegram/ui/PhotoViewer.java")
    strings = read("TMessagesProj/src/main/res/values/strings.xml")
    strings_ru = read("TMessagesProj/src/main/res/values-ru/strings.xml")

    require(shared, "public static boolean roundVideosAsRegularMedia;", "SharedConfig flag")
    require(shared, 'getBoolean("roundVideosAsRegularMedia", false)', "default-off load")
    require(shared, "toggleRoundVideosAsRegularMedia()", "SharedConfig toggle")
    require(shared, 'putBoolean("roundVideosAsRegularMedia", roundVideosAsRegularMedia)', "toggle persistence")

    require(message_object, "shouldOpenRoundVideoAsRegularMedia()", "round-video regular-media helper")
    require(message_object, "shouldDisplayRoundVideoInline()", "round-video inline helper")
    require(message_object, "SharedConfig.roundVideosAsRegularMedia && isRoundVideo() && !isRoundOnce()", "helper default-off condition")

    require(theme_activity, "roundVideosAsRegularMediaRow", "chat settings row")
    require(theme_activity, "SharedConfig.toggleRoundVideosAsRegularMedia()", "settings click toggles flag")
    require(theme_activity, "RoundVideosAsRegularMedia", "settings title binding")
    require(theme_activity, "RoundVideosAsRegularMediaInfo", "settings subtitle binding")

    require(chat_cell, "messageObject.shouldDisplayRoundVideoInline()", "cell inline-round display gate")
    require(chat_cell, "messageObject.shouldOpenRoundVideoAsRegularMedia()", "cell regular-media layout gate")
    require(chat_activity, "message.isVideoOrRoundVideoAsRegularMedia()", "tap opens round videos through media viewer")
    require(chat_activity, "!visibleMessage.shouldOpenRoundVideoAsRegularMedia()", "autoplay keeps special round path gated")
    require(photo_viewer, "isVideoOrRoundVideoAsRegularMedia()", "photo viewer accepts regular-media round videos as videos")

    require(strings, 'name="RoundVideosAsRegularMedia"', "English settings title")
    require(strings, 'name="RoundVideosAsRegularMediaInfo"', "English settings info")
    require(strings_ru, 'name="RoundVideosAsRegularMedia"', "Russian settings title")
    require(strings_ru, 'name="RoundVideosAsRegularMediaInfo"', "Russian settings info")

    print("round video regular-media mode contract OK")


if __name__ == "__main__":
    main()
