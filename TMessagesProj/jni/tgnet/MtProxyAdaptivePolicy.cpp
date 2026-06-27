/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyAdaptivePolicy.h"

#include <map>
#include <openssl/rand.h>
#include <pthread.h>

struct MtProxyTlsAutoProfileState {
    int32_t profileIndex = -1;
    uint32_t failures = 0;
};

static pthread_mutex_t mtProxyTlsAutoProfilesMutex = PTHREAD_MUTEX_INITIALIZER;
static std::map<std::string, MtProxyTlsAutoProfileState> tlsAutoRotateProfiles;

static uint64_t tlsAutoRotateSalt() {
    static uint64_t salt = 0;
    if (salt == 0) {
        RAND_bytes((uint8_t *) &salt, sizeof(salt));
        if (salt == 0) {
            salt = 0x9e3779b97f4a7c15ULL;
        }
    }
    return salt;
}

static uint64_t profileHash(uint64_t hash, const std::string &value) {
    for (char c : value) {
        hash ^= (uint8_t) c;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static int32_t autoRotatePoolProfile(int32_t index) {
    static const int32_t profiles[] = {
            MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID,
            MT_PROXY_TLS_PROFILE_YANDEX,
            MT_PROXY_TLS_PROFILE_CHROME_MODERN,
    };
    int32_t normalizedIndex = index % 3;
    if (normalizedIndex < 0) {
        normalizedIndex += 3;
    }
    return profiles[normalizedIndex];
}

static int32_t autoRotateInitialIndex(const std::string &key) {
    uint64_t hash = 0xcbf29ce484222325ULL ^ tlsAutoRotateSalt();
    hash = profileHash(hash, key);
    return (int32_t) (hash % 3);
}

MtProxyAdaptivePolicy::RecipeResult MtProxyAdaptivePolicy::applyRecipe(const RecipeInput &input) {
    RecipeResult result;
    result.recipeLevel = input.recipeLevel;
    result.clientHelloFragmentation = normalizeMtProxyClientHelloFragmentationOption(input.clientHelloFragmentation);
    result.effectiveTlsProfile = normalizeMtProxyTlsProfileOption(input.effectiveTlsProfile);
    result.connectionPatternMode = normalizeMtProxyConnectionPatternOption(input.connectionPatternMode);
    result.recordSizingMode = normalizeMtProxyRecordSizingOption(input.recordSizingMode);
    result.timingMode = normalizeMtProxyTimingOption(input.timingMode);
    result.startupCoverMode = normalizeMtProxyStartupCoverOption(input.startupCoverMode);
    if (!input.fakeTls || input.endpointKey.empty() || input.recipeLevel <= 0) {
        return result;
    }
    if (input.lastDiagnostic == "post_handshake_no_appdata") {
        if (result.recordSizingMode == MT_PROXY_RECORD_SIZING_OFF) {
            result.recordSizingMode = MT_PROXY_RECORD_SIZING_CONSERVATIVE;
            result.changed = true;
        }
        if (result.timingMode == MT_PROXY_TIMING_OFF) {
            result.timingMode = MT_PROXY_TIMING_GENTLE;
            result.changed = true;
        }
        if (result.startupCoverMode == MT_PROXY_STARTUP_COVER_OFF) {
            result.startupCoverMode = MT_PROXY_STARTUP_COVER_SOFT;
            result.changed = true;
        }
        if (input.recipeLevel >= 2 && result.connectionPatternMode != MT_PROXY_CONNECTION_PATTERN_STRICT) {
            if (result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_OFF
                    || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_SOFT
                    || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
                result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET;
                result.changed = true;
            }
        }
        return result;
    }
    if (input.recipeLevel >= 1 && result.clientHelloFragmentation == MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF) {
        result.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT;
        result.changed = true;
    }
    if (input.recipeLevel >= 2) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = adaptiveTlsProfile(input.configuredTlsProfile, result.effectiveTlsProfile);
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    }
    if (input.recipeLevel >= 3 && result.connectionPatternMode != MT_PROXY_CONNECTION_PATTERN_STRICT) {
        if (result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_OFF
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_SOFT
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
            result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET;
            result.changed = true;
        }
    }
    return result;
}

int32_t MtProxyAdaptivePolicy::resolveEffectiveTlsProfile(int32_t profile, const std::string &key) {
    profile = normalizeMtProxyTlsProfileOption(profile);
    if (profile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        if (profile == MT_PROXY_TLS_PROFILE_AUTO) {
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        }
        return profile;
    }

    pthread_mutex_lock(&mtProxyTlsAutoProfilesMutex);
    MtProxyTlsAutoProfileState &state = tlsAutoRotateProfiles[key];
    if (state.profileIndex < 0) {
        state.profileIndex = autoRotateInitialIndex(key);
    }
    int32_t result = autoRotatePoolProfile(state.profileIndex);
    pthread_mutex_unlock(&mtProxyTlsAutoProfilesMutex);
    return result;
}

MtProxyAdaptivePolicy::RotateResult MtProxyAdaptivePolicy::rotateTlsProfileOnFailureIfNeeded(const std::string &key, const std::string &diagnostic, int32_t previousProfile) {
    RotateResult result;
    result.previousProfile = normalizeMtProxyTlsProfileOption(previousProfile);
    if (key.empty() || !failureNeedsRecipe(diagnostic)) {
        return result;
    }
    pthread_mutex_lock(&mtProxyTlsAutoProfilesMutex);
    MtProxyTlsAutoProfileState &state = tlsAutoRotateProfiles[key];
    if (state.profileIndex < 0) {
        state.profileIndex = autoRotateInitialIndex(key);
    }
    state.profileIndex = (state.profileIndex + 1) % 3;
    state.failures++;
    result.failures = state.failures;
    result.nextProfile = autoRotatePoolProfile(state.profileIndex);
    pthread_mutex_unlock(&mtProxyTlsAutoProfilesMutex);
    result.rotated = true;
    return result;
}

bool MtProxyAdaptivePolicy::failureNeedsRecipe(const std::string &diagnostic) {
    if (diagnostic == "tcp_not_connected") {
        return false; // ClientHello was not sent, so JA4 did not cause this failure.
    }
    return diagnostic == "client_hello_sent_no_server_hello"
           || diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "post_handshake_no_appdata";
}

int32_t MtProxyAdaptivePolicy::adaptiveTlsProfile(int32_t configuredProfile, int32_t effectiveProfile) {
    configuredProfile = normalizeMtProxyTlsProfileOption(configuredProfile);
    if (configuredProfile != MT_PROXY_TLS_PROFILE_AUTO && configuredProfile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        return effectiveProfile;
    }
    switch (normalizeMtProxyTlsProfileOption(effectiveProfile)) {
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return MT_PROXY_TLS_PROFILE_CHROME_MODERN;
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
            return MT_PROXY_TLS_PROFILE_CHROME_MODERN;
        default:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
    }
}
