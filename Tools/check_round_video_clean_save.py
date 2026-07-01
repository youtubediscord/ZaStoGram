#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHAT = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java"
MEDIA = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/MediaController.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def require(text, needle, label):
    if needle not in text:
        raise SystemExit(f"missing {label}: {needle}")


def main():
    chat = CHAT.read_text(encoding="utf-8", errors="ignore")
    media = MEDIA.read_text(encoding="utf-8", errors="ignore")
    strings = STRINGS.read_text(encoding="utf-8", errors="ignore")
    strings_ru = STRINGS_RU.read_text(encoding="utf-8", errors="ignore")

    require(chat, "OPTION_SAVE_CLEAN_ROUND_VIDEO", "round-video clean-save menu option")
    require(chat, "selectedObject.isRoundVideo()", "round-video menu guard")
    require(chat, "MediaController.saveCleanRoundVideo(", "round-video clean-save handler")
    require(media, "saveCleanRoundVideo(", "clean round-video export entrypoint")
    require(media, "ROUND_VIDEO_CLEAN_CROP_RATIO", "safe center crop ratio")
    require(media, "MediaCodecVideoConvertor.ConvertVideoParams.of(", "real video transcode path")
    require(strings, 'name="SaveCleanRoundVideo"', "English clean-save string")
    require(strings_ru, 'name="SaveCleanRoundVideo"', "Russian clean-save string")

    print("round video clean-save contract OK")


if __name__ == "__main__":
    main()
