/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#ifndef MTPROXYADAPTIVEPOLICY_H
#define MTPROXYADAPTIVEPOLICY_H

#include <stdint.h>
#include <string>
#include "MtProxyOptions.h"

class MtProxyAdaptivePolicy {
public:
    struct RecipeInput {
        bool fakeTls = false;
        std::string endpointKey;
        std::string lastDiagnostic;
        int32_t recipeLevel = 0;
        int32_t clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
        int32_t configuredTlsProfile = MT_PROXY_TLS_PROFILE_AUTO;
        int32_t effectiveTlsProfile = MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        int32_t connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_OFF;
        int32_t recordSizingMode = MT_PROXY_RECORD_SIZING_OFF;
        int32_t timingMode = MT_PROXY_TIMING_OFF;
        int32_t startupCoverMode = MT_PROXY_STARTUP_COVER_OFF;
    };

    struct RecipeResult {
        bool changed = false;
        int32_t recipeLevel = 0;
        int32_t clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
        int32_t effectiveTlsProfile = MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        int32_t connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_OFF;
        int32_t recordSizingMode = MT_PROXY_RECORD_SIZING_OFF;
        int32_t timingMode = MT_PROXY_TIMING_OFF;
        int32_t startupCoverMode = MT_PROXY_STARTUP_COVER_OFF;
    };

    struct RotateResult {
        bool rotated = false;
        int32_t previousProfile = MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        int32_t nextProfile = MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        uint32_t failures = 0;
    };

    static RecipeResult applyRecipe(const RecipeInput &input);
    static int32_t resolveEffectiveTlsProfile(int32_t profile, const std::string &key);
    static RotateResult rotateTlsProfileOnFailureIfNeeded(const std::string &key, const std::string &diagnostic, int32_t previousProfile);
    static bool failureNeedsRecipe(const std::string &diagnostic);
    static int32_t adaptiveTlsProfile(int32_t configuredProfile, int32_t effectiveProfile);
};

#endif
