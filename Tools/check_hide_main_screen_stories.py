#!/usr/bin/env python3
"""Static guard for hiding the main-screen stories row from Chat Settings."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
THEME_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/ThemeActivity.java"
DIALOGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/DialogsActivity.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"

PREF_KEY = "hide_main_screen_stories"


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


def method_body_after(text: str, marker: str, signature: str) -> str:
    marker_index = text.find(marker)
    if marker_index < 0:
        return ""
    return method_body(text[marker_index:], signature)


def main() -> int:
    theme_activity = read(THEME_ACTIVITY)
    dialogs_activity = read(DIALOGS_ACTIVITY)
    strings = read(STRINGS)
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require(
        '<string name="HideMainScreenStories">Скрывать сторисы на главном экране</string>' in strings,
        "HideMainScreenStories string must use the settled Russian label",
    )
    require(
        '<string name="HideMainScreenStoriesInfo">Убирает ленту сторисов и кнопку публикации из списка чатов.</string>' in strings,
        "HideMainScreenStoriesInfo string must explain the main-screen scope",
    )

    require("private int hideMainScreenStoriesRow;" in theme_activity, "ThemeActivity must declare hideMainScreenStoriesRow")
    update_rows = method_body(theme_activity, "private void updateRows(boolean notify)")
    require("hideMainScreenStoriesRow = -1;" in update_rows, "updateRows must reset hideMainScreenStoriesRow")
    require(
        re.search(r"hideMainScreenStoriesRow\s*=\s*rowCount\+\+;[\s\S]*otherSectionRow\s*=\s*rowCount\+\+;", update_rows) is not None,
        "Chat Settings must place hideMainScreenStoriesRow in the Other settings section",
    )

    create_view = method_body(theme_activity, "public View createView(Context context)")
    require(PREF_KEY in create_view, f"ThemeActivity click handler must toggle {PREF_KEY}")
    require(
        "NotificationCenter.storiesEnabledUpdate" in create_view,
        "ThemeActivity must notify open chat lists after toggling the stories setting",
    )

    bind_holder = method_body_after(
        theme_activity,
        "private class ListAdapter extends RecyclerListView.SelectionAdapter",
        "public void onBindViewHolder(RecyclerView.ViewHolder holder, int position)",
    )
    require(
        "position == hideMainScreenStoriesRow" in bind_holder
        and "R.string.HideMainScreenStories" in bind_holder
        and "R.string.HideMainScreenStoriesInfo" in bind_holder
        and PREF_KEY in bind_holder,
        "ThemeActivity must bind hideMainScreenStoriesRow as a checked row with label and info",
    )

    hide_helper = method_body(dialogs_activity, "private boolean shouldHideMainScreenStories()")
    require(PREF_KEY in hide_helper, f"DialogsActivity.shouldHideMainScreenStories must read {PREF_KEY}")
    require("!isArchive()" in hide_helper, "The hide-stories preference must only affect the main dialogs screen, not archive")

    floating_visibility = method_body(dialogs_activity, "private void updateFloatingButtonVisibility(boolean animated)")
    require(
        "shouldHideMainScreenStories()" in floating_visibility
        and "floatingButtonStories.setButtonVisible(isVisible && !hideMainScreenStories" in floating_visibility,
        "DialogsActivity must hide the main-screen story FAB when the setting is enabled",
    )
    require(
        "storyHint.hide()" in floating_visibility,
        "DialogsActivity must hide the story hint when the setting hides main-screen stories",
    )

    stories_visibility = method_body(dialogs_activity, "public void updateStoriesVisibility(boolean animated)")
    require("shouldHideMainScreenStories()" in stories_visibility, "DialogsActivity.updateStoriesVisibility must use shouldHideMainScreenStories")
    require(
        re.search(r"hideMainScreenStories[\s\S]*newVisibility\s*=\s*false;", stories_visibility) is not None,
        "DialogsActivity must force stories visibility off when the setting is enabled",
    )
    require(
        re.search(r"hideMainScreenStories[\s\S]*onlySelfStories\s*=\s*false;", stories_visibility) is not None,
        "DialogsActivity must also hide the self-story placeholder when the setting is enabled",
    )

    notification_branch = method_body(dialogs_activity, "public void didReceivedNotification(int id, int account, Object... args)")
    require(
        "id == NotificationCenter.storiesEnabledUpdate" in notification_branch
        and "updateStoriesVisibility" in notification_branch
        and "updateFloatingButtonVisibility" in notification_branch,
        "DialogsActivity must refresh stories visibility and the story FAB when the setting notification arrives",
    )

    if failures:
        print("Hide main-screen stories check failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Hide main-screen stories check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
