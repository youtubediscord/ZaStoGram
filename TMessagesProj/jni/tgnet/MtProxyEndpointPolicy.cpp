/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyEndpointPolicy.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <map>
#include <openssl/rand.h>
#include <pthread.h>

static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_GENERIC = 0;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_MEDIA = 1;
static constexpr int64_t MT_PROXY_ENDPOINT_DNS_CACHE_TTL_MS = 30 * 60 * 1000;
static constexpr int64_t MT_PROXY_ENDPOINT_DNS_COALESCE_MS = 750;
static constexpr int64_t MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_MS = 650;
static constexpr int64_t MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_REPEAT_MS = 2200;
static constexpr int64_t MT_PROXY_ENDPOINT_INTERACTIVE_NETWORK_COOLDOWN_MAX_MS = 3500;
static constexpr int64_t MT_PROXY_ENDPOINT_MEDIA_NETWORK_COOLDOWN_MAX_MS = 5000;
static constexpr int64_t MT_PROXY_ENDPOINT_HEAVY_NETWORK_COOLDOWN_MAX_MS = 9000;
static constexpr int64_t MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS = 45 * 1000;
static constexpr int32_t MT_PROXY_ENDPOINT_RECIPE_MAX_LEVEL = 3;

struct MtProxyEndpointResilienceState {
    int64_t lastSuccessTime = 0;
    int64_t cooldownUntil = 0;
    int32_t hostResolveFailures = 0;
    int32_t tcpFailures = 0;
    int32_t handshakeFailures = 0;
    int32_t plainNoResponseFailures = 0;
    int32_t postHandshakeFailures = 0;
    int32_t recipeLevel = 0;
    std::string lastRecipeDiagnostic;
    int32_t activeTcpConnects = 0;
};

struct MtProxyDnsCacheState {
    std::string lastGoodIpv4;
    int64_t lastGoodIpv4Time = 0;
    int64_t resolveInFlightUntil = 0;
};

static pthread_mutex_t mtProxyEndpointPolicyMutex = PTHREAD_MUTEX_INITIALIZER;
static std::map<std::string, MtProxyEndpointResilienceState> proxyEndpointResilience;
static std::map<std::string, MtProxyDnsCacheState> proxyEndpointDnsCache;

static uint32_t endpointSecureRandomUint32() {
    uint32_t v;
    RAND_bytes((uint8_t *) &v, sizeof(v));
    return v;
}

static uint32_t endpointSecureRandomBounded(uint32_t bound) {
    if (bound <= 1) {
        return 0;
    }
    uint32_t threshold = (uint32_t) (-bound) % bound;
    uint32_t v;
    do {
        v = endpointSecureRandomUint32();
    } while (v < threshold);
    return v % bound;
}

static int64_t cooldownMs(MtProxyEndpointResilienceState &state, const std::string &diagnostic, int32_t mode, int32_t priority) {
    mode = normalizeMtProxyConnectionPatternOption(mode);
    int32_t penalty = 1;
    bool networkFailure = diagnostic == "host_resolve_failed" || diagnostic == "host_resolve_timeout" || diagnostic == "tcp_not_connected";
    if (diagnostic == "host_resolve_failed" || diagnostic == "host_resolve_timeout") {
        penalty = ++state.hostResolveFailures;
        state.tcpFailures = 0;
    } else if (diagnostic == "tcp_not_connected") {
        penalty = ++state.tcpFailures;
    } else if (diagnostic == "mtproxy_packet_sent_no_response" || diagnostic == "tcp_connected_no_pong") {
        penalty = ++state.plainNoResponseFailures;
    } else if (diagnostic == "post_handshake_no_appdata" || diagnostic == "dropped_early_after_appdata") {
        penalty = ++state.postHandshakeFailures;
    } else {
        penalty = ++state.handshakeFailures;
    }
    if (penalty > 4) {
        penalty = 4;
    }

    int64_t base;
    int64_t jitter;
    int64_t maxCooldown;
    if (networkFailure) {
        bool genericNetworkFailure = priority <= MT_PROXY_HANDSHAKE_PRIORITY_GENERIC;
        bool interactiveNetworkFailure = priority <= MT_PROXY_HANDSHAKE_PRIORITY_MEDIA;
        if (mode == MT_PROXY_CONNECTION_PATTERN_STRICT) {
            base = genericNetworkFailure ? 900 : (interactiveNetworkFailure ? 1300 : 2800);
            jitter = endpointSecureRandomBounded(genericNetworkFailure ? 701 : (interactiveNetworkFailure ? 1001 : 2201));
        } else if (mode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
            base = genericNetworkFailure ? 650 : (interactiveNetworkFailure ? 950 : 2200);
            jitter = endpointSecureRandomBounded(genericNetworkFailure ? 601 : (interactiveNetworkFailure ? 801 : 1601));
        } else if (mode == MT_PROXY_CONNECTION_PATTERN_QUIET) {
            base = genericNetworkFailure ? 750 : (interactiveNetworkFailure ? 1100 : 2400);
            jitter = endpointSecureRandomBounded(genericNetworkFailure ? 651 : (interactiveNetworkFailure ? 901 : 1701));
        } else {
            base = genericNetworkFailure ? 350 : (interactiveNetworkFailure ? 500 : 900);
            jitter = endpointSecureRandomBounded(genericNetworkFailure ? 351 : (interactiveNetworkFailure ? 451 : 801));
        }
        base += penalty * (genericNetworkFailure ? 250 : (interactiveNetworkFailure ? 450 : 900));
        maxCooldown = genericNetworkFailure
                ? MT_PROXY_ENDPOINT_INTERACTIVE_NETWORK_COOLDOWN_MAX_MS
                : (interactiveNetworkFailure ? MT_PROXY_ENDPOINT_MEDIA_NETWORK_COOLDOWN_MAX_MS : MT_PROXY_ENDPOINT_HEAVY_NETWORK_COOLDOWN_MAX_MS);
    } else if (mode == MT_PROXY_CONNECTION_PATTERN_STRICT) {
        base = 3500 + penalty * 2200;
        jitter = endpointSecureRandomBounded(3001);
        maxCooldown = 18000;
    } else if (mode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
        base = 2200 + penalty * 1600;
        jitter = endpointSecureRandomBounded(2201);
        maxCooldown = 14000;
    } else if (mode == MT_PROXY_CONNECTION_PATTERN_QUIET) {
        base = 1800 + penalty * 1200;
        jitter = endpointSecureRandomBounded(1601);
        maxCooldown = 10000;
    } else {
        base = 650 + penalty * 450;
        jitter = endpointSecureRandomBounded(701);
        maxCooldown = 4500;
    }
    int64_t cooldown = base + jitter;
    if (cooldown > maxCooldown) {
        cooldown = maxCooldown;
    }
    return cooldown;
}

static bool failureCanBeShadowedBySuccess(const std::string &diagnostic) {
    if (diagnostic == "dropped_early_after_appdata" || diagnostic == "dropped_after_appdata") {
        return false;
    }
    return diagnostic == "host_resolve_failed"
            || diagnostic == "host_resolve_timeout"
            || diagnostic == "tcp_not_connected"
            || diagnostic == "tcp_connected_no_pong"
            || diagnostic == "client_hello_sent_no_server_hello"
            || diagnostic == "server_hello_hmac_mismatch"
            || diagnostic == "mtproxy_packet_sent_no_response"
            || diagnostic == "post_handshake_no_appdata";
}

static int64_t usableSuccessRemainingMsLocked(const std::string &key, int64_t now) {
    if (key.empty()) {
        return 0;
    }
    auto it = proxyEndpointResilience.find(key);
    if (it == proxyEndpointResilience.end() || it->second.lastSuccessTime <= 0) {
        return 0;
    }
    int64_t elapsed = std::max<int64_t>(0, now - it->second.lastSuccessTime);
    if (elapsed >= MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS) {
        return 0;
    }
    return MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS - elapsed;
}

bool MtProxyEndpointPolicy::extractSslipIpv4Address(const std::string &host, struct in_addr *address, std::string *literalAddress) {
    static const char suffix[] = ".sslip.io";
    static const size_t suffixLength = sizeof(suffix) - 1;
    std::string hostKey = host;
    std::transform(hostKey.begin(), hostKey.end(), hostKey.begin(), [](unsigned char c) {
        return (char) ::tolower(c);
    });
    if (hostKey.size() <= suffixLength || hostKey.compare(hostKey.size() - suffixLength, suffixLength, suffix) != 0) {
        return false;
    }
    std::string ipv4Address = hostKey.substr(0, hostKey.size() - suffixLength);
    if (address != nullptr && inet_pton(AF_INET, ipv4Address.c_str(), &address->s_addr) != 1) {
        return false;
    }
    if (address == nullptr) {
        struct in_addr parsedAddress;
        if (inet_pton(AF_INET, ipv4Address.c_str(), &parsedAddress.s_addr) != 1) {
            return false;
        }
    }
    if (literalAddress != nullptr) {
        *literalAddress = ipv4Address;
    }
    return true;
}

std::string MtProxyEndpointPolicy::networkEndpointKeyFor(const std::string &host, uint16_t port) {
    std::string hostKey = host;
    std::transform(hostKey.begin(), hostKey.end(), hostKey.begin(), [](unsigned char c) {
        return (char) ::tolower(c);
    });
    return hostKey + ":" + std::to_string((unsigned int) port);
}

std::string MtProxyEndpointPolicy::admissionKeyFor(const std::string &host, uint16_t port, const std::string &domain) {
    std::string key = networkEndpointKeyFor(host, port);
    if (!domain.empty()) {
        key += ":";
        key += domain;
    }
    return key;
}

std::string MtProxyEndpointPolicy::endpointKeyFor(const std::string &host, uint16_t port, const char *secretKind, const std::string &domain) {
    std::string key = host + ":" + std::to_string((unsigned int) port);
    key += ":";
    key += secretKind != nullptr ? secretKind : "unknown";
    if (!domain.empty()) {
        key += ":";
        key += domain;
    }
    return key;
}

std::string MtProxyEndpointPolicy::dnsCacheKeyFor(const std::string &host, uint16_t port) {
    return networkEndpointKeyFor(host, port);
}

std::string MtProxyEndpointPolicy::stateKeyForPhase(const std::string &phase, const std::string &networkEndpointKey, const std::string &endpointKey) {
    if ((phase == "host_resolve_failed"
            || phase == "host_resolve_timeout"
            || phase == "tcp_not_connected"
            || phase == "tcp_connected_no_pong"
            || phase == "mtproxy_packet_sent_no_response"
            || phase == "dropped_early_after_appdata")
            && !networkEndpointKey.empty()) {
        return networkEndpointKey;
    }
    if (!endpointKey.empty()) {
        return endpointKey;
    }
    return networkEndpointKey;
}

bool MtProxyEndpointPolicy::failureNeedsCooldown(const std::string &diagnostic) {
    return diagnostic == "host_resolve_failed"
           || diagnostic == "host_resolve_timeout"
           || diagnostic == "tcp_not_connected"
           || diagnostic == "tcp_connected_no_pong"
           || diagnostic == "client_hello_sent_no_server_hello"
           || diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "mtproxy_packet_sent_no_response"
           || diagnostic == "post_handshake_no_appdata"
           || diagnostic == "dropped_early_after_appdata";
}

bool MtProxyEndpointPolicy::failureNeedsRecipe(const std::string &diagnostic) {
    return diagnostic == "client_hello_sent_no_server_hello"
           || diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "post_handshake_no_appdata";
}

int64_t MtProxyEndpointPolicy::cooldownMs(const std::string &diagnostic, int32_t connectionPatternMode, int32_t priority) {
    MtProxyEndpointResilienceState scratch;
    return ::cooldownMs(scratch, diagnostic, connectionPatternMode, priority);
}

MtProxyEndpointPolicy::CooldownResult MtProxyEndpointPolicy::readCooldown(const MtProxyEndpointContext &context, int64_t now) {
    CooldownResult result;
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    auto readCooldown = [&](const std::string &key) {
        if (key.empty()) {
            return;
        }
        auto it = proxyEndpointResilience.find(key);
        if (it != proxyEndpointResilience.end() && it->second.cooldownUntil > result.cooldownUntil) {
            result.cooldownUntil = it->second.cooldownUntil;
            result.key = key;
        }
    };
    readCooldown(context.networkEndpointKey);
    readCooldown(context.endpointKey);
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    result.active = result.cooldownUntil > now;
    if (result.active) {
        result.remainingMs = result.cooldownUntil - now;
    }
    return result;
}

MtProxyEndpointPolicy::TcpConnectGateResult MtProxyEndpointPolicy::beginTcpConnect(const std::string &networkEndpointKey, bool wasReady) {
    TcpConnectGateResult result;
    if (networkEndpointKey.empty()) {
        return result;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    MtProxyEndpointResilienceState &state = proxyEndpointResilience[networkEndpointKey];
    result.activeTcpConnects = state.activeTcpConnects;
    if (result.activeTcpConnects > 0) {
        result.shouldDelay = true;
    } else {
        state.activeTcpConnects++;
        result.activeTcpConnects = state.activeTcpConnects;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    if (result.shouldDelay) {
        result.delayMs = (uint32_t) ((wasReady ? MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_REPEAT_MS : MT_PROXY_ENDPOINT_TCP_CONNECT_GATE_MS) + endpointSecureRandomBounded(wasReady ? 701 : 351));
    }
    return result;
}

int32_t MtProxyEndpointPolicy::releaseTcpConnect(const std::string &networkEndpointKey) {
    if (networkEndpointKey.empty()) {
        return 0;
    }
    int32_t activeTcpConnects = 0;
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    MtProxyEndpointResilienceState &state = proxyEndpointResilience[networkEndpointKey];
    if (state.activeTcpConnects > 0) {
        state.activeTcpConnects--;
    }
    activeTcpConnects = state.activeTcpConnects;
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    return activeTcpConnects;
}

MtProxyEndpointPolicy::DnsCoalesceResult MtProxyEndpointPolicy::beginDnsCoalesce(const std::string &dnsCacheKey, int64_t now) {
    DnsCoalesceResult result;
    if (dnsCacheKey.empty()) {
        return result;
    }
    int64_t resolveInFlightUntil = 0;
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    MtProxyDnsCacheState &state = proxyEndpointDnsCache[dnsCacheKey];
    if (state.resolveInFlightUntil > now) {
        resolveInFlightUntil = state.resolveInFlightUntil;
        result.shouldDelay = true;
    } else {
        state.resolveInFlightUntil = now + MT_PROXY_ENDPOINT_DNS_COALESCE_MS;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    if (result.shouldDelay) {
        result.delayMs = (uint32_t) std::min<int64_t>(MT_PROXY_ENDPOINT_DNS_COALESCE_MS, std::max<int64_t>(50, resolveInFlightUntil - now));
    }
    return result;
}

bool MtProxyEndpointPolicy::useCachedHostAddress(const std::string &dnsCacheKey, int64_t now, std::string *cachedIpv4) {
    if (cachedIpv4 == nullptr || dnsCacheKey.empty()) {
        return false;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    auto it = proxyEndpointDnsCache.find(dnsCacheKey);
    if (it != proxyEndpointDnsCache.end()
            && !it->second.lastGoodIpv4.empty()
            && now - it->second.lastGoodIpv4Time <= MT_PROXY_ENDPOINT_DNS_CACHE_TTL_MS) {
        *cachedIpv4 = it->second.lastGoodIpv4;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    return !cachedIpv4->empty();
}

void MtProxyEndpointPolicy::storeResolvedAddress(const std::string &dnsCacheKey, const std::string &ip, int64_t now) {
    if (dnsCacheKey.empty() || ip.empty()) {
        return;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    MtProxyDnsCacheState &state = proxyEndpointDnsCache[dnsCacheKey];
    state.lastGoodIpv4 = ip;
    state.lastGoodIpv4Time = now;
    state.resolveInFlightUntil = 0;
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
}

MtProxyEndpointPolicy::FailureResult MtProxyEndpointPolicy::recordFailure(const MtProxyEndpointContext &context, const std::string &phase, int64_t now) {
    FailureResult result;
    if (!failureNeedsCooldown(phase) && !failureNeedsRecipe(phase)) {
        return result;
    }
    result.stateKey = stateKeyForPhase(phase, context.networkEndpointKey, context.endpointKey);
    if (result.stateKey.empty()) {
        return result;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    if (failureCanBeShadowedBySuccess(phase)) {
        result.usableSuccessRemainingMs = usableSuccessRemainingMsLocked(result.stateKey, now);
        if (result.usableSuccessRemainingMs > 0) {
            auto stateIt = proxyEndpointResilience.find(result.stateKey);
            if (stateIt != proxyEndpointResilience.end()) {
                result.recipeLevel = stateIt->second.recipeLevel;
            }
            result.shadowedByUsableSuccess = true;
            result.recorded = true;
            pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
            return result;
        }
    }
    MtProxyEndpointResilienceState &state = proxyEndpointResilience[result.stateKey];
    if (failureNeedsCooldown(phase)) {
        result.cooldownMs = ::cooldownMs(state, phase, context.connectionPatternMode, context.priority);
        if (result.cooldownMs > 0 && state.cooldownUntil < now + result.cooldownMs) {
            state.cooldownUntil = now + result.cooldownMs;
        }
    }
    result.recipeLevel = state.recipeLevel;
    if (context.fakeTls && failureNeedsRecipe(phase) && !context.endpointKey.empty()) {
        MtProxyEndpointResilienceState &recipeState = proxyEndpointResilience[context.endpointKey];
        if (recipeState.recipeLevel < MT_PROXY_ENDPOINT_RECIPE_MAX_LEVEL) {
            recipeState.recipeLevel++;
        }
        recipeState.lastRecipeDiagnostic = phase;
        result.recipeLevel = recipeState.recipeLevel;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    result.recorded = true;
    return result;
}

void MtProxyEndpointPolicy::recordHandshakeOk(const MtProxyEndpointContext &context, const char *reason) {
    if (reason == nullptr || strcmp(reason, "server_hello_hmac_ok") != 0 || context.networkEndpointKey.empty()) {
        return;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    auto it = proxyEndpointResilience.find(context.networkEndpointKey);
    if (it != proxyEndpointResilience.end()) {
        MtProxyEndpointResilienceState &state = it->second;
        bool onlyNetworkTransportFailures = state.handshakeFailures == 0
                && state.plainNoResponseFailures == 0
                && state.postHandshakeFailures == 0;
        state.hostResolveFailures = 0;
        state.tcpFailures = 0;
        if (onlyNetworkTransportFailures) {
            state.cooldownUntil = 0;
        }
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
}

MtProxyEndpointPolicy::DataPathSuccessResult MtProxyEndpointPolicy::recordDataPathSuccess(const MtProxyEndpointContext &context, const char *reason, int64_t now) {
    DataPathSuccessResult result;
    if (reason == nullptr
            || (strcmp(reason, "first_tls_app_recv") != 0
                    && strcmp(reason, "first_mtproxy_packet_recv") != 0)) {
        return result;
    }
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    resetStateForKey(context.networkEndpointKey, now, false);
    resetStateForKey(context.endpointKey, now, true);
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    result.accepted = true;
    return result;
}

int32_t MtProxyEndpointPolicy::recipeLevelForEndpoint(const std::string &endpointKey) {
    int32_t recipeLevel = 0;
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    auto it = proxyEndpointResilience.find(endpointKey);
    if (it != proxyEndpointResilience.end()) {
        recipeLevel = it->second.recipeLevel;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    return recipeLevel;
}

std::string MtProxyEndpointPolicy::lastRecipeDiagnosticForEndpoint(const std::string &endpointKey) {
    std::string diagnostic;
    pthread_mutex_lock(&mtProxyEndpointPolicyMutex);
    auto it = proxyEndpointResilience.find(endpointKey);
    if (it != proxyEndpointResilience.end()) {
        diagnostic = it->second.lastRecipeDiagnostic;
    }
    pthread_mutex_unlock(&mtProxyEndpointPolicyMutex);
    return diagnostic;
}

void MtProxyEndpointPolicy::resetStateForKey(const std::string &key, int64_t now, bool resetRecipe) {
    if (key.empty()) {
        return;
    }
    MtProxyEndpointResilienceState &state = proxyEndpointResilience[key];
    state.lastSuccessTime = now;
    state.cooldownUntil = 0;
    state.hostResolveFailures = 0;
    state.tcpFailures = 0;
    if (resetRecipe) {
        state.handshakeFailures = 0;
        state.plainNoResponseFailures = 0;
        state.postHandshakeFailures = 0;
        state.recipeLevel = 0;
        state.lastRecipeDiagnostic.clear();
    }
}
