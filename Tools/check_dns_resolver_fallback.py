#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
MTPROXY_ALL = ROOT / "Tools/check_mtproxy_all.py"
RUNTIME_VERIFIER = ROOT / "Tools/verify_mtproxy_runtime_logs.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    brace = text.find("{", start)
    if brace == -1:
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
    return text[start:]


def run_runtime_log_checks(failures: list[str]) -> None:
    base = "\n".join(
        [
            "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) mtproxy_disconnect transport_state=closed epoll_registered=0 admission_active=0 tcp_gate_active=0",
            "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196",
            "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup endpoint_handshake_ok reason=server_hello_hmac_ok",
            "logcat.txt:4: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
            "logcat.txt:5: 06-25 20:31:30.100 connection(0x1) mtproxy_startup endpoint_data_path_success network_key=198.51.100.1:443 key=198.51.100.1:443:cdn.example reason=first_tls_app_recv",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bad = tmp_path / "bad_dns.txt"
        good = tmp_path / "good_dns.txt"
        bad.write_text(base + "\nlogcat.txt:6: 06-25 20:31:30.200 E/tmessages FileNotFoundException: https://www.google.com/resolve?name=gosuslugi.v6.rocks&type=A\n", encoding="utf-8")
        good.write_text(base + "\nlogcat.txt:6: 06-25 20:31:30.200 D/tmessages dns_resolver fallback provider=google_json_doh host=gosuslugi.v6.rocks reason=FileNotFoundException\n", encoding="utf-8")
        bad_result = subprocess.run([sys.executable, str(RUNTIME_VERIFIER), str(bad)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        good_result = subprocess.run([sys.executable, str(RUNTIME_VERIFIER), str(good)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(
            bad_result.returncode != 0 and "dns resolver must not log expected DoH fallback as E/tmessages /resolve" in bad_result.stderr,
            "runtime verifier must reject E/tmessages FileNotFoundException ... /resolve",
            failures,
        )
        require(
            good_result.returncode == 0,
            good_result.stderr.strip() or "runtime verifier must accept D/tmessages dns_resolver fallback logs",
            failures,
        )


def main() -> int:
    failures: list[str] = []
    connections = read(CONNECTIONS)
    mtproxy_all = read(MTPROXY_ALL)
    runtime_verifier = read(RUNTIME_VERIFIER)
    resolver_class = method_body(connections, "private static class ResolveHostByNameTask")
    resolver_body = method_body(resolver_class, "protected ResolvedDomain doInBackground")
    get_host_body = method_body(connections, "public static void getHostByName")
    load_doh = method_body(connections, "private static DohJsonResponse loadDohJson")
    chain_index = connections.find("private static final HostResolver[] HOST_RESOLVER_CHAIN")

    require("import java.io.FileNotFoundException;" in connections, "resolver must import FileNotFoundException for controlled DoH fallback", failures)
    require("import java.net.UnknownHostException;" in connections, "resolver must import UnknownHostException for controlled DNS fallback", failures)
    require("import java.net.URLEncoder;" in connections, "DoH URL builder must URL-encode host/query parameters", failures)
    require("private interface HostResolver" in connections, "host resolver chain must use a HostResolver abstraction", failures)
    require("private static class ResolveContext" in connections, "host resolver chain must carry ResolveContext state", failures)
    for class_name in ("DnsCacheResolver", "SystemDnsResolver", "GoogleJsonDohResolver", "CloudflareJsonDohResolver"):
        require(f"private static class {class_name}" in connections, f"host resolver chain must include {class_name}", failures)
    require(
        chain_index >= 0
        and chain_index < connections.find("new DnsCacheResolver()", chain_index)
        < connections.find("new SystemDnsResolver()", chain_index)
        < connections.find("new GoogleJsonDohResolver()", chain_index)
        < connections.find("new CloudflareJsonDohResolver()", chain_index),
        "host resolver order must be cache -> system DNS -> Google JSON DoH -> Cloudflare JSON DoH",
        failures,
    )
    require("resolveHost(currentHostName" in resolver_body, "ResolveHostByNameTask must delegate to resolveHost chain", failures)
    require("dnsCache.get(hostName)" in get_host_body and "isFresh(now)" in get_host_body, "getHostByName must use fresh in-memory DNS cache before async resolving", failures)
    require("dnsCache.put(context.host, resolved)" in connections or "dnsCache.put(currentHostName, result)" in connections, "successful resolver results must be cached", failures)
    require(
        "List<String> ipv4" in connections
        and "List<String> ipv6" in connections
        and "expiresAtMs" in connections
        and "staleExpiresAtMs" in connections
        and "String source" in connections,
        "ResolvedDomain must store IPv4, IPv6, fresh expiry, stale expiry, and source",
        failures,
    )
    require(
        '"https://dns.google/resolve"' in connections
        and '"https://cloudflare-dns.com/dns-query"' in connections
        and "edns_client_subnet" in connections
        and '"https://www.google.com/resolve"' not in connections
        and '"https://dns.google.com/resolve"' not in connections
        and '"https://mozilla.cloudflare-dns.com/dns-query"' not in connections,
        "DoH endpoints must be dns.google/resolve and cloudflare-dns.com/dns-query only",
        failures,
    )
    require(
        'addRequestProperty("Host",' not in connections,
        "resolver code must not set a manual Host header that differs from the URL host",
        failures,
    )
    require(
        'addRequestProperty("User-Agent", DOH_USER_AGENT)' in load_doh
        and 'addRequestProperty("Accept", "application/dns-json")' in load_doh
        and "setConnectTimeout(connectTimeout)" in load_doh
        and "setReadTimeout(readTimeout)" in load_doh
        and "URLEncoder.encode" in load_doh,
        "shared JSON DoH loader must own headers, timeouts, URL encoding, and reads",
        failures,
    )
    require(
        "HOST_RESOLVER_SYSTEM_TIMEOUT_MS = 1500" in connections
        and "HOST_RESOLVER_DOH_CONNECT_TIMEOUT_MS = 1000" in connections
        and "HOST_RESOLVER_DOH_READ_TIMEOUT_MS = 1500" in connections
        and "HOST_RESOLVER_TOTAL_TIMEOUT_MS = 3000" in connections
        and "remainingDnsBudgetMs(context" in connections,
        "resolver must bound system DNS, DoH attempts, and total DNS budget",
        failures,
    )
    require("tryAndroidDnsResolverA(context.host)" in connections and "tryInetAddressA(context.host)" in connections, "system resolver must try Android DNS before InetAddress", failures)
    require("DnsResolver.getInstance().query(null, hostName, DnsResolver.TYPE_A" in connections, "Android DnsResolver must use TYPE_A for host resolver", failures)
    require("CancellationSignal cancellationSignal = new CancellationSignal();" in connections and "cancellationSignal.cancel();" in connections, "Android DNS queries must be cancellable", failures)
    require("InetAddress.getAllByName(hostName)" in connections, "system resolver must keep InetAddress fallback", failures)
    require(
        'logDnsResult("system", "success"' in connections
        and 'logDnsResult("google_json_doh", "success"' in connections
        and 'logDnsResult("cloudflare_json_doh", "success"' in connections
        and 'FileLog.d("dns_resolver fallback provider="' in connections
        and 'FileLog.d("dns_resolver provider="' in connections,
        "DNS resolver must log neutral dns_resolver success/fallback lines",
        failures,
    )
    require(
        "catch (FileNotFoundException | UnknownHostException | SocketTimeoutException | SSLException e)" in connections
        and "FileLog.e(e, false)" in connections,
        "expected DoH failures must be debug fallback logs while unexpected throwables stay error logs",
        failures,
    )
    require(
        "dns resolver must not log expected DoH fallback as E/tmessages /resolve" in runtime_verifier
        and "dns_resolver fallback provider=" in runtime_verifier,
        "runtime verifier must enforce the DNS log acceptance criteria",
        failures,
    )
    require('"check_dns_resolver_fallback.py"' in mtproxy_all, "full MTProxy guard suite must include DNS resolver fallback guard", failures)

    for class_name in ("GoogleDnsLoadTask", "MozillaDnsLoadTask"):
        task = method_body(connections, f"private static class {class_name}")
        require("loadDohJson(" in task and "openConnection()" not in task, f"{class_name} must use the shared JSON DoH loader", failures)
        require("catch (FileNotFoundException | UnknownHostException" in task and "logDohExpectedFailure(" in task, f"{class_name} must treat expected DoH failures as debug fallback noise", failures)
        require("dnsConfigDomain(currentAccount)" in task, f"{class_name} must use the shared DNS config domain helper", failures)

    run_runtime_log_checks(failures)

    if failures:
        print("DNS resolver fallback guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("DNS resolver fallback guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
