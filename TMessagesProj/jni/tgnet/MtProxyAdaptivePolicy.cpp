/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyAdaptivePolicy.h"
#include "MtProxyServerFlightParser.h"

#include <map>
#include <openssl/rand.h>
#include <pthread.h>
#include <vector>

struct MtProxyTlsAutoProfileState {
    int32_t profileIndex = -1;
    uint32_t failures = 0;
};

static pthread_mutex_t mtProxyTlsAutoProfilesMutex = PTHREAD_MUTEX_INITIALIZER;
static std::map<std::string, MtProxyTlsAutoProfileState> tlsAutoRotateProfiles;

static constexpr int32_t MT_PROXY_ALTERNATE_PROFILE_COUNT = 4;

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
            MT_PROXY_TLS_PROFILE_ANDROID_CHROME,
            MT_PROXY_TLS_PROFILE_YANDEX,
            MT_PROXY_TLS_PROFILE_FIREFOX,
    };
    int32_t normalizedIndex = index % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    if (normalizedIndex < 0) {
        normalizedIndex += MT_PROXY_ALTERNATE_PROFILE_COUNT;
    }
    return profiles[normalizedIndex];
}

static int32_t autoRotateInitialIndex(const std::string &key) {
    uint64_t hash = 0xcbf29ce484222325ULL ^ tlsAutoRotateSalt();
    hash = profileHash(hash, key);
    return (int32_t) (hash % MT_PROXY_ALTERNATE_PROFILE_COUNT);
}

static const char *adaptiveTlsProfileName(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_AUTO:
            return "auto";
        case MT_PROXY_TLS_PROFILE_FIREFOX:
            return "firefox";
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
            return "android_chrome";
        case MT_PROXY_TLS_PROFILE_YANDEX:
            return "yandex";
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return "firefox_android";
        case MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP:
            return "android_okhttp";
        case MT_PROXY_TLS_PROFILE_AUTO_ROTATE:
            return "auto_rotate";
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return "chrome_modern";
        case MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE:
            return "legacy_no_grease_no_4469_no_modern_extensions";
        default:
            return "android_chrome";
    }
}

bool MtProxyAdaptivePolicy::profileUsesGrease(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
        case MT_PROXY_TLS_PROFILE_FIREFOX:
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
        case MT_PROXY_TLS_PROFILE_YANDEX:
        case MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP:
            return true;
        default:
            return false;
    }
}

static bool profileUsesModernExtensions(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
        case MT_PROXY_TLS_PROFILE_FIREFOX:
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
        case MT_PROXY_TLS_PROFILE_YANDEX:
            return true;
        default:
            return false;
    }
}

static int32_t alternateCompatibilityTlsProfile(int32_t alternateProfileIndex) {
    static const int32_t profiles[] = {
            MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID,
            MT_PROXY_TLS_PROFILE_ANDROID_CHROME,
            MT_PROXY_TLS_PROFILE_YANDEX,
            MT_PROXY_TLS_PROFILE_FIREFOX,
    };
    int32_t normalizedIndex = alternateProfileIndex % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    if (normalizedIndex < 0) {
        normalizedIndex += MT_PROXY_ALTERNATE_PROFILE_COUNT;
    }
    return profiles[normalizedIndex];
}

static bool serverHelloParserVariantAllowed(MtProxyRecoveryAction action) {
    return action.kind == MtProxyRecoveryActionKind::AdvanceParserAllowed;
}

uint32_t MtProxyAdaptivePolicy::sniVariantMask(int32_t variant) {
    if (variant < 0 || variant >= SNI_VARIANT_COUNT) {
        return 0;
    }
    return 1U << (uint32_t) variant;
}

const char *MtProxyAdaptivePolicy::clientHelloFamilyName(int32_t family) {
    switch (family) {
        case CLIENT_HELLO_CHROME_MODERN_SOFT_FRAGMENT:
            return "chrome_modern_soft_fragment";
        case CLIENT_HELLO_CHROME_MODERN_NO_FRAGMENT:
            return "chrome_modern_no_fragment";
        case CLIENT_HELLO_ANDROID_CHROME_NO_FRAGMENT:
            return "android_chrome_no_fragment";
        case CLIENT_HELLO_FIREFOX_ANDROID_NO_FRAGMENT:
            return "firefox_android_no_fragment";
        case CLIENT_HELLO_LEGACY_NO_GREASE_NO_MODERN_EXTENSIONS:
            return "legacy_no_grease_no_modern_extensions";
        case CLIENT_HELLO_LEGACY_TLS12_MINIMAL:
            return "legacy_tls12_minimal";
        default:
            return "chrome_modern_soft_fragment";
    }
}

const char *MtProxyAdaptivePolicy::sniVariantName(int32_t variant) {
    switch (variant) {
        case SNI_ORIGINAL:
            return "original_sni";
        case SNI_SANITIZED:
            return "sanitized_sni";
        case SNI_LOWERCASE_ASCII:
            return "lowercase_ascii_sni";
        case SNI_NO_TRAILING_DOT:
            return "no_trailing_dot_sni";
        case SNI_PUNYCODE:
            return "punycode_sni";
        case SNI_OPTIONAL_NO_SNI:
            return "optional_no_sni";
        default:
            return "original_sni";
    }
}

const char *MtProxyAdaptivePolicy::parserVariantName(int32_t parserVariant) {
    switch (parserVariant) {
        case PARSER_STANDARD_HMAC:
            return "standard_hmac_parser";
        case PARSER_LENIENT_RECORD:
            return "lenient_record_parser";
        case PARSER_TOLERATE_EXTRA_RECORDS_BEFORE_SERVER_HELLO:
            return "tolerate_extra_records_before_server_hello";
        case PARSER_TOLERATE_CCS_TICKET_ORDERING:
            return "tolerate_ccs_ticket_ordering";
        case PARSER_TOLERATE_FRAGMENTED_SERVER_HELLO:
            return "tolerate_fragmented_server_hello";
        case PARSER_TOLERATE_TLS_ALERT_EXACT_DESC:
            return "tolerate_tls_alert_exact_desc";
        default:
            return "standard_hmac_parser";
    }
}

const char *MtProxyAdaptivePolicy::classicVariantName(int32_t classicVariant) {
    switch (classicVariant) {
        case CLASSIC_STANDARD_INTERMEDIATE:
            return "standard_intermediate";
        case CLASSIC_RANDOMIZED_INTERMEDIATE:
            return "randomized_intermediate";
        case CLASSIC_ABRIDGED_FALLBACK:
            return "abridged_fallback";
        case CLASSIC_INTERMEDIATE_FALLBACK:
            return "intermediate_fallback";
        case CLASSIC_NONE:
        default:
            return "none";
    }
}

static int32_t parserModeForVariant(int32_t parserVariant) {
    switch (parserVariant) {
        case MtProxyAdaptivePolicy::PARSER_LENIENT_RECORD:
            return MT_PROXY_SERVER_HELLO_PARSER_LENIENT_RECORD;
        case MtProxyAdaptivePolicy::PARSER_TOLERATE_EXTRA_RECORDS_BEFORE_SERVER_HELLO:
            return MT_PROXY_SERVER_HELLO_PARSER_EXTRA_RECORDS;
        case MtProxyAdaptivePolicy::PARSER_TOLERATE_CCS_TICKET_ORDERING:
            return MT_PROXY_SERVER_HELLO_PARSER_CCS_TICKET_ORDERING;
        case MtProxyAdaptivePolicy::PARSER_TOLERATE_FRAGMENTED_SERVER_HELLO:
            return MT_PROXY_SERVER_HELLO_PARSER_FRAGMENTED_SERVER_HELLO;
        case MtProxyAdaptivePolicy::PARSER_TOLERATE_TLS_ALERT_EXACT_DESC:
            return MT_PROXY_SERVER_HELLO_PARSER_TLS_ALERT_EXACT_DESC;
        case MtProxyAdaptivePolicy::PARSER_STANDARD_HMAC:
        default:
            return MT_PROXY_SERVER_HELLO_PARSER_STANDARD;
    }
}

static bool sniVariantAllowed(uint32_t mask, int32_t variant) {
    return (mask & MtProxyAdaptivePolicy::sniVariantMask(variant)) != 0;
}

static std::vector<MtProxyAdaptivePolicy::RecipeCursor> buildRecipeCursorLadder(uint32_t allowedSniVariants, bool classicFallbackAllowed, MtProxyRecoveryAction action) {
    std::vector<MtProxyAdaptivePolicy::RecipeCursor> ladder;
    if (allowedSniVariants == 0) {
        allowedSniVariants = MtProxyAdaptivePolicy::sniVariantMask(MtProxyAdaptivePolicy::SNI_SANITIZED);
    }
    int32_t parserLimit = serverHelloParserVariantAllowed(action)
            ? MtProxyAdaptivePolicy::PARSER_VARIANT_COUNT
            : MtProxyAdaptivePolicy::PARSER_STANDARD_HMAC + 1;
    for (int32_t sniVariant = MtProxyAdaptivePolicy::SNI_ORIGINAL; sniVariant <= MtProxyAdaptivePolicy::SNI_PUNYCODE; sniVariant++) {
        if (!sniVariantAllowed(allowedSniVariants, sniVariant)) {
            continue;
        }
        for (int32_t family = 0; family < MtProxyAdaptivePolicy::CLIENT_HELLO_FAMILY_COUNT; family++) {
            for (int32_t parser = 0; parser < parserLimit; parser++) {
                MtProxyAdaptivePolicy::RecipeCursor cursor;
                cursor.family = family;
                cursor.sniVariant = sniVariant;
                cursor.parserVariant = parser;
                cursor.classicVariant = MtProxyAdaptivePolicy::CLASSIC_NONE;
                ladder.push_back(cursor);
            }
        }
    }
    if (sniVariantAllowed(allowedSniVariants, MtProxyAdaptivePolicy::SNI_OPTIONAL_NO_SNI)) {
        for (int32_t family = 0; family < MtProxyAdaptivePolicy::CLIENT_HELLO_FAMILY_COUNT; family++) {
            for (int32_t parser = 0; parser < parserLimit; parser++) {
                MtProxyAdaptivePolicy::RecipeCursor cursor;
                cursor.family = family;
                cursor.sniVariant = MtProxyAdaptivePolicy::SNI_OPTIONAL_NO_SNI;
                cursor.parserVariant = parser;
                cursor.classicVariant = MtProxyAdaptivePolicy::CLASSIC_NONE;
                ladder.push_back(cursor);
            }
        }
    }
    if (classicFallbackAllowed) {
        for (int32_t classicVariant = MtProxyAdaptivePolicy::CLASSIC_STANDARD_INTERMEDIATE; classicVariant < MtProxyAdaptivePolicy::CLASSIC_VARIANT_COUNT; classicVariant++) {
            MtProxyAdaptivePolicy::RecipeCursor cursor;
            cursor.classicVariant = classicVariant;
            cursor.sniVariant = MtProxyAdaptivePolicy::SNI_OPTIONAL_NO_SNI;
            ladder.push_back(cursor);
        }
    }
    return ladder;
}

MtProxyAdaptivePolicy::RecipeCursor MtProxyAdaptivePolicy::initialCursor(uint32_t allowedSniVariants) {
    MtProxyRecoveryAction action;
    action.kind = MtProxyRecoveryActionKind::AdvanceClientHelloOnly;
    std::vector<RecipeCursor> ladder = buildRecipeCursorLadder(allowedSniVariants, false, action);
    if (!ladder.empty()) {
        return ladder.front();
    }
    RecipeCursor cursor;
    cursor.sniVariant = SNI_SANITIZED;
    return cursor;
}

bool MtProxyAdaptivePolicy::nextCursorForRecovery(RecipeCursor *cursor, MtProxyRecoveryAction action, uint32_t allowedSniVariants, bool classicFallbackAllowed) {
    if (cursor == nullptr || !mtProxyRecoveryActionAdvancesRecipe(action)) {
        return false;
    }
    std::vector<RecipeCursor> ladder = buildRecipeCursorLadder(allowedSniVariants, classicFallbackAllowed, action);
    if (ladder.empty()) {
        return false;
    }
    for (size_t i = 0; i < ladder.size(); i++) {
        const RecipeCursor &candidate = ladder[i];
        if (candidate.family == cursor->family
                && candidate.sniVariant == cursor->sniVariant
                && candidate.parserVariant == cursor->parserVariant
                && candidate.classicVariant == cursor->classicVariant) {
            if (i + 1 >= ladder.size()) {
                return false;
            }
            uint32_t nextGeneration = cursor->generation + 1;
            *cursor = ladder[i + 1];
            cursor->generation = nextGeneration;
            return true;
        }
    }
    *cursor = ladder.front();
    cursor->generation++;
    return true;
}

bool MtProxyAdaptivePolicy::nextCursor(RecipeCursor *cursor, const std::string &diagnostic, uint32_t allowedSniVariants, bool classicFallbackAllowed) {
    MtProxyRecoveryAction action = mtProxyRecoveryActionForPhase(diagnostic, 0);
    return nextCursorForRecovery(cursor, action, allowedSniVariants, classicFallbackAllowed);
}

static int32_t greaseProbeTlsProfile(int32_t configuredProfile, int32_t effectiveProfile) {
    configuredProfile = normalizeMtProxyTlsProfileOption(configuredProfile);
    effectiveProfile = normalizeMtProxyTlsProfileOption(effectiveProfile);
    if (MtProxyAdaptivePolicy::profileUsesGrease(configuredProfile)) {
        return configuredProfile;
    }
    if (MtProxyAdaptivePolicy::profileUsesGrease(effectiveProfile)) {
        return effectiveProfile;
    }
    return MT_PROXY_TLS_PROFILE_ANDROID_CHROME;
}

static std::string sniForVariant(const MtProxyAdaptivePolicy::RecipeInput &input, int32_t variant) {
    switch (variant) {
        case MtProxyAdaptivePolicy::SNI_ORIGINAL:
            return input.originalSni.empty() ? input.sni : input.originalSni;
        case MtProxyAdaptivePolicy::SNI_SANITIZED:
            return input.sanitizedSni.empty() ? input.sni : input.sanitizedSni;
        case MtProxyAdaptivePolicy::SNI_LOWERCASE_ASCII:
            return input.lowercaseAsciiSni.empty() ? input.sni : input.lowercaseAsciiSni;
        case MtProxyAdaptivePolicy::SNI_NO_TRAILING_DOT:
            return input.noTrailingDotSni.empty() ? input.sni : input.noTrailingDotSni;
        case MtProxyAdaptivePolicy::SNI_PUNYCODE:
            return input.punycodeSni.empty() ? input.sni : input.punycodeSni;
        case MtProxyAdaptivePolicy::SNI_OPTIONAL_NO_SNI:
            return "";
        default:
            return input.sni;
    }
}

MtProxyAdaptivePolicy::CompatibilityRecipe MtProxyAdaptivePolicy::recipeForCursor(const RecipeInput &input, const RecipeCursor &cursor) {
    CompatibilityRecipe recipe;
    recipe.cursor = cursor;
    recipe.familyName = clientHelloFamilyName(cursor.family);
    recipe.sniVariantName = sniVariantName(cursor.sniVariant);
    recipe.parserVariantName = parserVariantName(cursor.parserVariant);
    recipe.classicVariantName = classicVariantName(cursor.classicVariant);
    recipe.clientHelloSni = sniForVariant(input, cursor.sniVariant);
    recipe.experimentalNoSni = cursor.sniVariant == SNI_OPTIONAL_NO_SNI;
    recipe.connectionPatternMode = normalizeMtProxyConnectionPatternOption(input.connectionPatternMode);
    recipe.recordSizingMode = normalizeMtProxyRecordSizingOption(input.recordSizingMode);
    recipe.timingMode = normalizeMtProxyTimingOption(input.timingMode);
    recipe.startupCoverMode = normalizeMtProxyStartupCoverOption(input.startupCoverMode);
    recipe.serverHelloParserMode = parserModeForVariant(cursor.parserVariant);
    recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_CHROME_MODERN;

    if (cursor.classicVariant != CLASSIC_NONE) {
        recipe.transportMode = "classic_obfuscated";
        recipe.effectiveTlsProfile = normalizeMtProxyTlsProfileOption(input.effectiveTlsProfile);
        recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
        recipe.serverHelloParserMode = MT_PROXY_SERVER_HELLO_PARSER_STANDARD;
        recipe.tlsProfile = adaptiveTlsProfileName(recipe.effectiveTlsProfile);
        recipe.useGrease = false;
        recipe.useModernExtensions = false;
        return recipe;
    }

    recipe.transportMode = input.fakeTls ? "faketls_ee" : "classic_obfuscated";
    switch (cursor.family) {
        case CLIENT_HELLO_CHROME_MODERN_SOFT_FRAGMENT:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_CHROME_MODERN;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT;
            break;
        case CLIENT_HELLO_CHROME_MODERN_NO_FRAGMENT:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_CHROME_MODERN;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
            break;
        case CLIENT_HELLO_ANDROID_CHROME_NO_FRAGMENT:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_ANDROID_CHROME;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
            break;
        case CLIENT_HELLO_FIREFOX_ANDROID_NO_FRAGMENT:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
            break;
        case CLIENT_HELLO_LEGACY_NO_GREASE_NO_MODERN_EXTENSIONS:
        case CLIENT_HELLO_LEGACY_TLS12_MINIMAL:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
            break;
        default:
            recipe.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_CHROME_MODERN;
            recipe.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT;
            break;
    }

    if (input.probeGrease || input.greaseSupported) {
        recipe.effectiveTlsProfile = greaseProbeTlsProfile(input.configuredTlsProfile, recipe.effectiveTlsProfile);
    }
    recipe.tlsProfile = adaptiveTlsProfileName(recipe.effectiveTlsProfile);
    recipe.fragmentClientHello = recipe.clientHelloFragmentation != MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    recipe.useGrease = profileUsesGrease(recipe.effectiveTlsProfile);
    recipe.useModernExtensions = profileUsesModernExtensions(recipe.effectiveTlsProfile);
    return recipe;
}

MtProxyAdaptivePolicy::RecipeResult MtProxyAdaptivePolicy::applyRecipe(const RecipeInput &input) {
    if (input.useRecipeCursor) {
        CompatibilityRecipe compatibilityRecipe = recipeForCursor(input, input.cursor);
        RecipeResult result;
        result.recipeLevel = input.recipeLevel;
        result.clientHelloFragmentation = compatibilityRecipe.clientHelloFragmentation;
        result.effectiveTlsProfile = compatibilityRecipe.effectiveTlsProfile;
        result.serverHelloParserMode = compatibilityRecipe.serverHelloParserMode;
        result.clientHelloSni = compatibilityRecipe.clientHelloSni;
        result.connectionPatternMode = compatibilityRecipe.connectionPatternMode;
        result.recordSizingMode = compatibilityRecipe.recordSizingMode;
        result.timingMode = compatibilityRecipe.timingMode;
        result.startupCoverMode = compatibilityRecipe.startupCoverMode;
        result.changed = result.clientHelloFragmentation != normalizeMtProxyClientHelloFragmentationOption(input.clientHelloFragmentation)
                || result.effectiveTlsProfile != normalizeMtProxyTlsProfileOption(input.effectiveTlsProfile)
                || result.serverHelloParserMode != normalizeMtProxyServerHelloParserOption(input.serverHelloParserMode)
                || result.clientHelloSni != input.sni
                || result.connectionPatternMode != normalizeMtProxyConnectionPatternOption(input.connectionPatternMode)
                || result.recordSizingMode != normalizeMtProxyRecordSizingOption(input.recordSizingMode)
                || result.timingMode != normalizeMtProxyTimingOption(input.timingMode)
                || result.startupCoverMode != normalizeMtProxyStartupCoverOption(input.startupCoverMode);
        return result;
    }

    RecipeResult result;
    result.recipeLevel = input.recipeLevel;
    result.clientHelloFragmentation = normalizeMtProxyClientHelloFragmentationOption(input.clientHelloFragmentation);
    result.effectiveTlsProfile = normalizeMtProxyTlsProfileOption(input.effectiveTlsProfile);
    result.serverHelloParserMode = normalizeMtProxyServerHelloParserOption(input.serverHelloParserMode);
    result.connectionPatternMode = normalizeMtProxyConnectionPatternOption(input.connectionPatternMode);
    result.recordSizingMode = normalizeMtProxyRecordSizingOption(input.recordSizingMode);
    result.timingMode = normalizeMtProxyTimingOption(input.timingMode);
    result.startupCoverMode = normalizeMtProxyStartupCoverOption(input.startupCoverMode);
    bool useGreaseProfile = input.probeGrease || (input.greaseSupported && input.recipeLevel <= 1);
    if (useGreaseProfile) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = greaseProbeTlsProfile(input.configuredTlsProfile, result.effectiveTlsProfile);
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    } else if (input.fakeTls && input.recipeLevel == 2) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    } else if (input.fakeTls && input.recipeLevel >= 3) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = alternateCompatibilityTlsProfile(input.alternateProfileIndex);
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    }
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
    if (input.recipeLevel >= 1 && result.clientHelloFragmentation != MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF) {
        result.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
        result.changed = true;
    }
    if (serverHelloParserVariantAllowed(mtProxyRecoveryActionForPhase(input.lastDiagnostic, 0))
            && input.recipeLevel >= 4
            && result.serverHelloParserMode != MT_PROXY_SERVER_HELLO_PARSER_RESERVED) {
        result.serverHelloParserMode = MT_PROXY_SERVER_HELLO_PARSER_RESERVED;
        result.changed = true;
    }
    if (input.recipeLevel >= 4 && result.connectionPatternMode != MT_PROXY_CONNECTION_PATTERN_STRICT) {
        if (result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_OFF
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_SOFT
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
            result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET;
            result.changed = true;
        }
    }
    return result;
}

MtProxyAdaptivePolicy::MtProxyRecipe MtProxyAdaptivePolicy::recipeForResult(const RecipeInput &input, const RecipeResult &result) {
    MtProxyRecipe recipe;
    recipe.transportMode = input.fakeTls ? "faketls_ee" : "classic_obfuscated";
    recipe.tlsProfile = adaptiveTlsProfileName(result.effectiveTlsProfile);
    recipe.fragmentClientHello = result.clientHelloFragmentation != MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    recipe.useGrease = MtProxyAdaptivePolicy::profileUsesGrease(result.effectiveTlsProfile);
    recipe.useModernExtensions = profileUsesModernExtensions(result.effectiveTlsProfile);
    recipe.serverHelloParser = mtProxyServerHelloParserName(result.serverHelloParserMode);
    recipe.sni = result.clientHelloSni.empty() ? input.sni : result.clientHelloSni;
    return recipe;
}

MtProxyAdaptivePolicy::MtProxyRecipe MtProxyAdaptivePolicy::recipeForCompatibilityRecipe(const CompatibilityRecipe &recipe) {
    MtProxyRecipe result;
    result.transportMode = recipe.transportMode;
    result.tlsProfile = recipe.tlsProfile;
    result.fragmentClientHello = recipe.fragmentClientHello;
    result.useGrease = recipe.useGrease;
    result.useModernExtensions = recipe.useModernExtensions;
    result.serverHelloParser = recipe.parserVariantName;
    result.sni = recipe.clientHelloSni;
    return result;
}

std::string MtProxyAdaptivePolicy::recipeId(const CompatibilityRecipe &recipe) {
    return recipe.transportMode
            + "+" + recipe.familyName
            + "+" + recipe.sniVariantName
            + "+" + recipe.parserVariantName
            + "+classic=" + recipe.classicVariantName
            + "+" + recipe.tlsProfile
            + "+" + (recipe.fragmentClientHello ? "soft_fragment" : "no_fragment")
            + "+" + (recipe.useGrease ? "grease" : "no_grease")
            + "+" + (recipe.useModernExtensions ? "modern_extensions" : "no_modern_extensions")
            + (recipe.experimentalNoSni ? "+experimental_no_sni=1" : "+experimental_no_sni=0")
            + "+sni=" + (recipe.clientHelloSni.empty() ? "none" : recipe.clientHelloSni);
}

std::string MtProxyAdaptivePolicy::recipeId(const MtProxyRecipe &recipe) {
    return recipe.transportMode
            + "+" + recipe.tlsProfile
            + "+" + (recipe.fragmentClientHello ? "soft_fragment" : "no_fragment")
            + "+" + (recipe.useGrease ? "grease" : "no_grease")
            + "+" + (recipe.useModernExtensions ? "modern_extensions" : "no_modern_extensions")
            + "+" + recipe.serverHelloParser
            + "+sni=" + (recipe.sni.empty() ? "none" : recipe.sni);
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
    state.profileIndex = (state.profileIndex + 1) % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    state.failures++;
    result.failures = state.failures;
    result.nextProfile = autoRotatePoolProfile(state.profileIndex);
    pthread_mutex_unlock(&mtProxyTlsAutoProfilesMutex);
    result.rotated = true;
    return result;
}

bool MtProxyAdaptivePolicy::failureNeedsRecipe(const std::string &diagnostic) {
    if (diagnostic == "tcp_not_connected"
            || diagnostic == "tcp_connection_refused"
            || diagnostic == "tcp_connect_timeout") {
        return false; // ClientHello was not sent, so JA4 did not cause this failure.
    }
    bool recipePhase = diagnostic == "true_client_hello_timeout"
            || diagnostic == "faketls_server_hello_wait_timeout"
            || diagnostic == "server_closed_after_client_hello"
            || diagnostic == "client_hello_sent_no_server_hello"
            || diagnostic == "tls_alert_after_client_hello"
            || diagnostic == "short_tls_response_after_client_hello"
            || diagnostic == "unrecognized_response_after_client_hello"
            || diagnostic == "unrecognized_tls_response_after_client_hello"
            || diagnostic == "server_hello_hmac_mismatch";
    if (!recipePhase) {
        return false;
    }
    return mtProxyRecoveryActionAdvancesRecipe(mtProxyRecoveryActionForPhase(diagnostic, 0));
}

int32_t MtProxyAdaptivePolicy::compatibilityTlsProfile(int32_t configuredProfile, int32_t effectiveProfile, int32_t recipeLevel) {
    (void) configuredProfile;
    effectiveProfile = normalizeMtProxyTlsProfileOption(effectiveProfile);
    if (recipeLevel <= 1) {
        return effectiveProfile;
    }
    if (recipeLevel == 2) {
        if (effectiveProfile == MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE) {
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        }
        return MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
    }
    if (recipeLevel == 3) {
        return alternateCompatibilityTlsProfile(0);
    }
    return alternateCompatibilityTlsProfile(MT_PROXY_ALTERNATE_PROFILE_COUNT - 1);
}

int32_t MtProxyAdaptivePolicy::adaptiveTlsProfile(int32_t configuredProfile, int32_t effectiveProfile) {
    configuredProfile = normalizeMtProxyTlsProfileOption(configuredProfile);
    if (configuredProfile != MT_PROXY_TLS_PROFILE_AUTO && configuredProfile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        return effectiveProfile;
    }
    switch (normalizeMtProxyTlsProfileOption(effectiveProfile)) {
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        case MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE:
            return MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        default:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
    }
}
