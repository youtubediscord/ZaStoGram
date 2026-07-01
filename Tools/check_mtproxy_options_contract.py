#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]

JAVA_OPTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/MtProxyOptions.java"
JAVA_CM = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
WRAPPER = ROOT / "TMessagesProj/jni/TgNetWrapper.cpp"
NATIVE_OPTIONS = ROOT / "TMessagesProj/jni/tgnet/MtProxyOptions.h"
MANAGER_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.h"
MANAGER_CPP = ROOT / "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
PROXY_CHECK = ROOT / "TMessagesProj/jni/tgnet/ProxyCheckInfo.h"
SOCKET_H = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    failures: list[str] = []
    java_options = read(JAVA_OPTIONS)
    java_cm = read(JAVA_CM)
    wrapper = read(WRAPPER)
    native_options = read(NATIVE_OPTIONS)
    manager_h = read(MANAGER_H)
    manager_cpp = read(MANAGER_CPP)
    proxy_check = read(PROXY_CHECK)
    socket_h = read(SOCKET_H)

    require(JAVA_OPTIONS.exists(), "Java MtProxyOptions class must exist", failures)
    for field in (
        "final int tlsProfile",
        "final int clientHelloFragmentation",
        "final int connectionPatternMode",
        "final int recordSizingMode",
        "final int timingMode",
        "final int startupCoverMode",
    ):
        require(field in java_options, f"Java MtProxyOptions must expose immutable {field}", failures)
    require("static MtProxyOptions resolve(" in java_options, "MtProxyOptions.resolve(...) must build normalized runtime options", failures)
    require("static MtProxyOptions disabled()" in java_options, "MtProxyOptions.disabled() must provide an all-default option object", failures)

    require(NATIVE_OPTIONS.exists(), "native MtProxyOptions.h must exist", failures)
    require("struct MtProxyOptions" in native_options, "native MtProxyOptions struct must exist", failures)
    for field in (
        "tlsProfile",
        "clientHelloFragmentation",
        "connectionPatternMode",
        "recordSizingMode",
        "timingMode",
        "startupCoverMode",
    ):
        require(field in native_options, f"native MtProxyOptions must contain {field}", failures)
    require("normalizeMtProxyOptions" in native_options + manager_cpp, "native options must be normalized once at native boundary", failures)

    require(
        "native_setProxySettings(int currentAccount, String address, int port, String username, String password, String secret, MtProxyOptions options, int activationGeneration, String activationOrigin)" in java_cm,
        "Java native_setProxySettings must take MtProxyOptions object, not positional ints",
        failures,
    )
    require(
        "native_checkProxy(int currentAccount, String address, int port, String username, String password, String secret, MtProxyOptions options, RequestTimeDelegate requestTimeDelegate)" in java_cm,
        "Java native_checkProxy must take MtProxyOptions object before RequestTimeDelegate",
        failures,
    )
    require("MtProxyOptions.resolve(" in java_cm, "Java proxy call sites must use MtProxyOptions.resolve(...)", failures)
    require("MtProxyOptions.disabled()" in java_cm, "Java disabled proxy path must use MtProxyOptions.disabled()", failures)

    require("readMtProxyOptions(JNIEnv *env, jobject options)" in wrapper, "JNI wrapper must read MtProxyOptions through a named helper", failures)
    require("Lorg/telegram/tgnet/MtProxyOptions;" in wrapper, "JNI signatures must reference MtProxyOptions object", failures)
    require("IIIIII" not in wrapper, "JNI signatures must not contain the old six-int IIIIII MTProxy option suffix", failures)
    require("jint mtProxyTlsProfile" not in wrapper, "JNI wrapper must not receive positional mtProxyTlsProfile", failures)

    require("MtProxyOptions proxyMtProxyOptions" in manager_h, "ConnectionsManager must store one MtProxyOptions struct", failures)
    require("setProxySettings(std::string address, uint16_t port, std::string username, std::string password, std::string secret, const MtProxyOptions &options, uint32_t activationGeneration, std::string activationOrigin)" in manager_h, "native setProxySettings must take MtProxyOptions", failures)
    require("checkProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, const MtProxyOptions &options" in manager_h, "native checkProxy must take MtProxyOptions", failures)
    require("MtProxyOptions mtProxyOptions" in proxy_check, "ProxyCheckInfo must store one MtProxyOptions struct", failures)
    require("setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, const MtProxyOptions &options)" in socket_h, "ConnectionSocket override proxy must take MtProxyOptions", failures)

    positional_patterns = [
        r"mtProxyTlsProfile,\s*mtProxyClientHelloFragmentation,\s*mtProxyConnectionPatternMode,\s*mtProxyRecordSizingMode,\s*mtProxyTimingMode,\s*mtProxyStartupCoverMode",
        r"int32_t\s+proxyTlsProfile\s*=",
        r"int32_t\s+proxyClientHelloFragmentation\s*=",
        r"int32_t\s+mtProxyTlsProfile\s*=",
    ]
    combined_native = "\n".join([manager_h, manager_cpp, proxy_check, socket_h])
    for pattern in positional_patterns:
        require(re.search(pattern, combined_native) is None, f"native code must not keep positional MTProxy option pattern: {pattern}", failures)

    if failures:
        print("MTProxy options contract guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("MTProxy options contract guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
