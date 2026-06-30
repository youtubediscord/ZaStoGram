#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GRADLE_PATH = ROOT / "TMessagesProj_AppStandalone" / "build.gradle"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "build-apk.yml"


ABI_FLAVORS = {
    "arm64": {
        "gradle_task_flavor": "Arm64",
        "flavor_dir": "arm64",
        "abi": "arm64-v8a",
        "version_code": "11",
        "artifact": "ZaStoGram-standalone-arm64-v8a",
        "ccache_key": "ccache-arm64-v8a-standalone",
    },
    "armv7": {
        "gradle_task_flavor": "Armv7",
        "flavor_dir": "armv7",
        "abi": "armeabi-v7a",
        "version_code": "12",
        "artifact": "ZaStoGram-standalone-armeabi-v7a",
        "ccache_key": "ccache-armeabi-v7a-standalone",
    },
    "x86": {
        "gradle_task_flavor": "X86",
        "flavor_dir": "x86",
        "abi": "x86",
        "version_code": "13",
        "artifact": "ZaStoGram-standalone-x86",
        "ccache_key": "ccache-x86-standalone",
    },
    "x64": {
        "gradle_task_flavor": "X64",
        "flavor_dir": "x64",
        "abi": "x86_64",
        "version_code": "14",
        "artifact": "ZaStoGram-standalone-x86_64",
        "ccache_key": "ccache-x86_64-standalone",
    },
}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"Missing required file: {path.relative_to(ROOT)}")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def find_named_block(text: str, name: str, *, start: int = 0) -> str | None:
    match = re.search(rf"(?m)^[ \t]*{re.escape(name)}[ \t]*\{{", text[start:])
    if not match:
        return None

    block_start = start + match.start()
    brace_start = text.find("{", block_start)
    depth = 0
    for index in range(brace_start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[block_start : index + 1]
    return None


def check_gradle(gradle_text: str) -> list[str]:
    errors: list[str] = []
    product_flavors = find_named_block(gradle_text, "productFlavors")
    if product_flavors is None:
        return ["Gradle file does not define productFlavors"]

    afat = find_named_block(product_flavors, "afat")
    if afat is None:
        errors.append("Gradle file must keep afat flavor as universal fallback")
    else:
        for abi in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64"):
            if f'"{abi}"' not in afat:
                errors.append(f"afat fallback is missing ABI {abi}")

    for flavor, expected in ABI_FLAVORS.items():
        block = find_named_block(product_flavors, flavor)
        if block is None:
            errors.append(f"Missing standalone ABI flavor {flavor}")
            continue

        abi = expected["abi"]
        if f'abiFilters "{abi}"' not in block:
            errors.append(f"Flavor {flavor} must restrict ndk.abiFilters to {abi}")

        version_code = expected["version_code"]
        if not re.search(rf"abiVersionCode[ \t]*=[ \t]*{re.escape(version_code)}\b", block):
            errors.append(f"Flavor {flavor} must use abiVersionCode = {version_code}")

        if "AndroidManifest_standalone.xml" not in block:
            errors.append(f"Flavor {flavor} must keep the standalone manifest")

    if "output.versionCodeOverride = defaultConfig.versionCode * 100 + variant.productFlavors.get(0).abiVersionCode" not in gradle_text:
        errors.append("Gradle version-code derivation must stay centralized on abiVersionCode with a two-digit ABI suffix")

    if "standaloneBuildFlavors = [\"afat\", \"arm64\", \"armv7\", \"x86\", \"x64\"]" not in gradle_text:
        errors.append("variantFilter must keep an explicit allow-list for afat and the ABI standalone flavors")

    if "!names.any { standaloneBuildFlavors.contains(it) }" not in gradle_text:
        errors.append("variantFilter must allow ABI standalone flavors through names.any")

    return errors


def check_workflow(workflow_text: str) -> list[str]:
    errors: list[str] = []

    required_literals = [
        "contents: write",
        "fail-fast: false",
        '":TMessagesProj_AppStandalone:assemble${{ matrix.flavor }}Standalone"',
        "TMessagesProj_AppStandalone/build/outputs/apk/${{ matrix.flavor_dir }}/standalone",
        "dist/${{ matrix.artifact }}.apk",
        "python3 Tools/check_mtproxy_all.py",
        "python3 Tools/check_plugin_python_deps.py",
        "python3 Tools/check_plugin_utils_javadoc.py",
        "python3 Tools/check_zasto_edit_history_contract.py",
        "release:",
        "needs: build",
        "actions/download-artifact@v4",
        "pattern: ZaStoGram-standalone-*",
        "merge-multiple: true",
        "github.run_number",
        "github.run_attempt",
        "gh release create \"$TAG\" dist-release/*.apk",
        "--prerelease",
        "--target \"$GITHUB_SHA\"",
    ]
    for literal in required_literals:
        if literal not in workflow_text:
            errors.append(f"Workflow is missing required contract literal: {literal}")

    if "assembleAfatStandalone" in workflow_text:
        errors.append("Workflow must not build the universal assembleAfatStandalone task")

    if re.search(r"(?m)tag(_name)?\s*:\s*(latest|nightly|prerelease|standalone|apk)\s*$", workflow_text):
        errors.append("Workflow must not publish to a shared rolling release tag")

    if "gh release upload" in workflow_text and "--clobber" in workflow_text:
        errors.append("Workflow must not clobber release assets; each run needs a fresh prerelease tag")

    for expected in ABI_FLAVORS.values():
        matrix_literals = [
            f"flavor: {expected['gradle_task_flavor']}",
            f"flavor_dir: {expected['flavor_dir']}",
            f"abi: {expected['abi']}",
            f"artifact: {expected['artifact']}",
            f"ccache_key: {expected['ccache_key']}",
            f"name: ${{{{ matrix.artifact }}}}",
            f"path: dist/${{{{ matrix.artifact }}}}.apk",
        ]
        for literal in matrix_literals:
            if literal not in workflow_text:
                errors.append(f"Workflow is missing matrix/upload value: {literal}")

    return errors


def main() -> int:
    errors = []
    errors.extend(check_gradle(read_text(GRADLE_PATH)))
    errors.extend(check_workflow(read_text(WORKFLOW_PATH)))

    if errors:
        print("Build APK workflow guard failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Build APK workflow guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
