#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
FILE_LOADER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileLoader.java"
FILE_LOAD_OPERATION = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java"
ANIMATED_STREAM = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger/AnimatedFileDrawableStream.java"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def extract_method(text: str, signature: str) -> str:
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
    failures: list[str] = []
    file_loader = read(FILE_LOADER)
    file_load_operation = read(FILE_LOAD_OPERATION)
    animated_stream = read(ANIMATED_STREAM)
    load_file_internal = extract_method(file_loader, "private FileLoadOperation loadFileInternal(")
    invalid_name = extract_method(file_loader, "private boolean isInvalidAttachFileName(")
    fail_invalid = extract_method(file_loader, "private boolean failInvalidFileLoad(")

    require(load_file_internal, "FileLoader.loadFileInternal() must exist", failures)
    require(invalid_name, "FileLoader must centralize invalid attach-name checks", failures)
    require(fail_invalid, "FileLoader must have a soft-fail path for invalid file locations", failures)
    require(
        "public static final int ERROR_INVALID_LOCATION" in file_loader,
        "FileLoader must expose ERROR_INVALID_LOCATION for invalid document/location failures",
        failures,
    )
    require(
        'FileLog.e(new RuntimeException("cant get hash' not in file_loader
        and 'throw new RuntimeException("cant get hash' not in file_loader,
        "missing document hash must not create or throw RuntimeException",
        failures,
    )
    require(
        "TextUtils.isEmpty(fileName)" in invalid_name
        and 'fileName.contains("" + Integer.MIN_VALUE)' in invalid_name
        and 'fileName.startsWith("0_0")' in invalid_name,
        "invalid attach-name check must reject empty, Integer.MIN_VALUE, and 0_0 document hashes",
        failures,
    )
    require(
        "failInvalidFileLoad(fileName, document, secureDocument, webDocument, location, imageLocation, parentObject, priority, cacheType)" in load_file_internal,
        "loadFileInternal() must route invalid locations through the soft-fail helper",
        failures,
    )
    if "failInvalidFileLoad(" in load_file_internal and "loadOperationPathsUI.put" in load_file_internal:
        require(
            load_file_internal.index("failInvalidFileLoad(") < load_file_internal.index("loadOperationPathsUI.put"),
            "invalid locations must fail before UI load state is registered",
            failures,
        )
    require(
        'FileLog.e("file_loader_missing_hash document=" + safeDocInfo(document)' in fail_invalid
        and 'requestClass=" + classifyProxyWarmupRequest(' in fail_invalid,
        "missing document hash log must include safe document info and request class without an exception stack",
        failures,
    )
    require(
        "loadOperationPathsUI.remove(safeFileName);" in fail_invalid
        and "delegate.fileDidFailedLoad(safeFileName, ERROR_INVALID_LOCATION);" in fail_invalid,
        "invalid locations must clean load UI state and notify the FileLoader delegate",
        failures,
    )
    require(
        "messageObject.getDocument() != null" in fail_invalid,
        "invalid download cleanup must not call DownloadController with a MessageObject that has no document",
        failures,
    )
    require(
        "private String safeDocInfo(" in file_loader
        and "document.id" in file_loader
        and "document.dc_id" in file_loader
        and "document.access_hash" in file_loader
        and "document.file_reference" in file_loader,
        "safeDocInfo() must log document identifiers without dumping the whole TL object",
        failures,
    )
    require(
        'throw new RuntimeException("!!!")' not in file_load_operation,
        "FileLoadOperation must not crash file queues with placeholder RuntimeException(\"!!!\")",
        failures,
    )
    require(
        'throw new RuntimeException("Out of limit"' not in file_load_operation,
        "FileLoadOperation encrypted padding size guard must fail the operation instead of throwing",
        failures,
    )
    require(
        "file_load_preload_offset_out_of_range" in file_load_operation
        and "return 0;" in extract_method(file_load_operation, "private long findNextPreloadDownloadOffset("),
        "FileLoadOperation preload offset overflow must log and abandon preload instead of throwing",
        failures,
    )
    require(
        "file_load_padding_limit_out_of_range" in file_load_operation,
        "FileLoadOperation encrypted padding size guard must emit structured diagnostics",
        failures,
    )
    require(
        'FileLog.e(new RuntimeException("infinity stream reading!!!"))' not in animated_stream,
        "AnimatedFileDrawableStream canceled read loop must not create RuntimeException stack logs",
        failures,
    )
    require(
        "animated_file_stream_cancelled_read_loop" in animated_stream,
        "AnimatedFileDrawableStream canceled read loop must log a structured non-exception warning",
        failures,
    )

    if failures:
        print("FileLoader invalid location guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    print("FileLoader invalid location guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
