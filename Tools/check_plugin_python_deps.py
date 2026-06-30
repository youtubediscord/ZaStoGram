#!/usr/bin/env python3
"""Guard the bundled Python packages expected by common exteraGram plugins."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_GRADLE = ROOT / "TMessagesProj" / "build.gradle"

REQUIRED_PACKAGES = {
    "Pillow": "provides PIL for image-processing plugins",
    "pyfiglet": "used by ASCII art generator plugins",
    "requests": "used by networked plugin helpers",
}


def fail(message: str) -> int:
    print("Plugin Python dependency guard failed:", file=sys.stderr)
    print(f"- {message}", file=sys.stderr)
    return 1


def installed_packages(gradle_text: str) -> set[str]:
    packages: set[str] = set()
    for match in re.finditer(r'(?m)^[ \t]*install[ \t]+"([^"]+)"', gradle_text):
        packages.add(match.group(1))
    return packages


def main() -> int:
    try:
        gradle_text = BUILD_GRADLE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return fail(f"Missing {BUILD_GRADLE.relative_to(ROOT)}")

    found = installed_packages(gradle_text)
    missing = [
        f"{package} ({reason})"
        for package, reason in REQUIRED_PACKAGES.items()
        if package not in found
    ]

    if missing:
        print("Plugin Python dependency guard failed:", file=sys.stderr)
        for item in missing:
            print(f"- Missing Chaquopy pip dependency: {item}", file=sys.stderr)
        return 1

    print("Plugin Python dependency guard passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
