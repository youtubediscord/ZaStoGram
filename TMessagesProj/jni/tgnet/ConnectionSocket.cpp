/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2015-2018.
 */

#include <cassert>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <cerrno>
#include <sys/socket.h>
#include <memory.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <utility>
#include <vector>
#include <openssl/bn.h>
#include "ByteStream.h"
#include "ConnectionSocket.h"
#include "FileLog.h"
#include "Defines.h"
#include "ConnectionsManager.h"
#include "EventObject.h"
#include "NativeByteBuffer.h"
#include "Timer.h"
#include "BuffersStorage.h"
#include "Connection.h"
#include <random>
#include <pthread.h>

static pthread_mutex_t proxyHandshakeSchedulerMutex = PTHREAD_MUTEX_INITIALIZER;

static constexpr int32_t MT_PROXY_TLS_PROFILE_FIREFOX = 1;
static constexpr int32_t MT_PROXY_TLS_PROFILE_ANDROID_CHROME = 2;
static constexpr int32_t MT_PROXY_TLS_PROFILE_YANDEX = 3;
static constexpr int32_t MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID = 4;
static constexpr int32_t MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP = 5;

static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_BYPASS = -1;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_GENERIC = 0;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_MEDIA = 1;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_PUSH = 2;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_DOWNLOAD = 3;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_UPLOAD = 4;
static constexpr int32_t MT_PROXY_HANDSHAKE_PRIORITY_PROXY_CHECK = 5;

static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_ADMISSION = 1;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_FREEZE = 2;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_SERVER_HELLO = 3;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_CLIENT_HELLO_FRAGMENT = 4;
static constexpr int32_t MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF = 0;
static constexpr int32_t MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT = 1;
static constexpr int64_t MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS = 4500;
static constexpr int64_t MT_PROXY_SERVER_HELLO_HMAC_WAIT_MS = 900;
static constexpr bool MT_PROXY_HANDSHAKE_ADMISSION_ENABLED = false;
static constexpr bool MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED = false;
static constexpr bool MT_PROXY_HANDSHAKE_CLOSE_ON_FREEZE_ENABLED = true;
static constexpr size_t MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES = 64 * 1024;
static constexpr size_t MT_PROXY_TLS_DIGEST_SIZE = 32;
static constexpr uint8_t MT_PROXY_TLS_RECORD_CHANGE_CIPHER_SPEC = 0x14;
static constexpr uint8_t MT_PROXY_TLS_RECORD_ALERT = 0x15;
static constexpr uint8_t MT_PROXY_TLS_RECORD_APPLICATION_DATA = 0x17;

static bool mtProxyExtractSslipIpv4Address(const std::string &host, struct in_addr *address, std::string *literalAddress) {
    static const char suffix[] = ".sslip.io";
    static const size_t suffixLength = sizeof(suffix) - 1;
    if (host.size() <= suffixLength || host.compare(host.size() - suffixLength, suffixLength, suffix) != 0) {
        return false;
    }
    std::string ipv4Address = host.substr(0, host.size() - suffixLength);
    if (inet_pton(AF_INET, ipv4Address.c_str(), &address->s_addr) != 1) {
        return false;
    }
    if (literalAddress != nullptr) {
        *literalAddress = ipv4Address;
    }
    return true;
}

static const char *mtProxySecretKindName(const std::string &secret) {
    if (secret.empty()) {
        return "none";
    }
    if (secret.size() >= 17 && secret[0] == '\xdd') {
        return "dd";
    }
    if (secret.size() > 17 && secret[0] == '\xee') {
        return "ee";
    }
    return "legacy";
}

static const char *mtProxyDisconnectReasonName(int32_t reason) {
    switch (reason) {
        case 0:
            return "drop";
        case 1:
            return "socket_error_or_eof";
        case 2:
            return "timeout_waiting_connect_or_pending_requests";
        default:
            return "unknown";
    }
}

static const char *mtProxySocketErrorName(int32_t error) {
    if (error == 0) {
        return "none";
    }
    if (error < 0) {
        return "internal";
    }
    return strerror(error);
}

struct MtProxyHandshakeQueuedRequest {
    ConnectionSocket *socket = nullptr;
    uint32_t generation = 0;
    int32_t priority = MT_PROXY_HANDSHAKE_PRIORITY_PROXY_CHECK;
    int64_t queuedAt = 0;
    bool ipv6 = false;
};

struct MtProxyHandshakeEndpointState {
    int32_t activeHandshakes = 0;
    int32_t recentSuccesses = 0;
    int32_t freezePenalty = 0;
    int64_t lastSuccessTime = 0;
    int64_t cooldownUntil = 0;
    std::vector<MtProxyHandshakeQueuedRequest> queuedRequests;
};

static std::map<std::string, MtProxyHandshakeEndpointState> proxyHandshakeEndpoints;

// Crypto-secure RNG for variable bytes inside the fake TLS profile: extension order and
// ECH/padding lengths. Transport timing/data-path stays on the tsrman-proven code path.
static uint32_t secureRandomUint32() {
    uint32_t v;
    RAND_bytes((uint8_t *) &v, sizeof(v));
    return v;
}

// Unbiased uniform value in [0, bound) via rejection sampling (avoids modulo bias).
static uint32_t secureRandomBounded(uint32_t bound) {
    if (bound <= 1) {
        return 0;
    }
    uint32_t threshold = (uint32_t) (-bound) % bound; // == 2^32 mod bound
    uint32_t v;
    do {
        v = secureRandomUint32();
    } while (v < threshold);
    return v % bound;
}

static bool mtProxyVerifyServerHelloHmac(const std::string &secret, const uint8_t *clientRandom, const uint8_t *responseBytes, size_t responseSize) {
    if (responseSize < 43 || responseSize > MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES) {
        return false;
    }
    std::vector<uint8_t> hmacInput(MT_PROXY_TLS_DIGEST_SIZE + responseSize);
    memcpy(hmacInput.data(), clientRandom, MT_PROXY_TLS_DIGEST_SIZE);
    memcpy(hmacInput.data() + MT_PROXY_TLS_DIGEST_SIZE, responseBytes, responseSize);
    memset(hmacInput.data() + MT_PROXY_TLS_DIGEST_SIZE + 11, 0, MT_PROXY_TLS_DIGEST_SIZE);

    uint8_t digest[MT_PROXY_TLS_DIGEST_SIZE];
    uint32_t outLength = 0;
    HMAC(EVP_sha256(), secret.data(), secret.size(), hmacInput.data(), hmacInput.size(), digest, &outLength);
    return outLength == MT_PROXY_TLS_DIGEST_SIZE && memcmp(digest, responseBytes + 11, MT_PROXY_TLS_DIGEST_SIZE) == 0;
}

static uint32_t mtProxyHandshakeGrantDelay() {
    return 90 + secureRandomBounded(161);
}

static uint32_t mtProxyHandshakeRetryDelay(int64_t now, int64_t cooldownUntil, int32_t priority) {
    uint32_t baseDelay = priority <= MT_PROXY_HANDSHAKE_PRIORITY_MEDIA ? 180 : 420;
    uint32_t delay = baseDelay + secureRandomBounded(priority <= MT_PROXY_HANDSHAKE_PRIORITY_MEDIA ? 181 : 421);
    if (MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED && cooldownUntil > now) {
        int64_t cooldownDelay = cooldownUntil - now;
        if (cooldownDelay > 5000) {
            cooldownDelay = 5000;
        }
        if ((int64_t) delay > cooldownDelay) {
            delay = (uint32_t) cooldownDelay;
        }
    }
    if (delay < 50) {
        delay = 50;
    }
    return delay;
}

static int32_t mtProxyHandshakeActiveLimit(const MtProxyHandshakeEndpointState &state, int64_t now) {
    if (MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED && state.cooldownUntil > now) {
        return 1;
    }
    if (state.recentSuccesses >= 2 && now - state.lastSuccessTime < 120000) {
        return 2;
    }
    return 1;
}

static bool mtProxyHandshakeHasHigherPriorityQueued(const MtProxyHandshakeEndpointState &state, int32_t priority) {
    for (const auto &request : state.queuedRequests) {
        if (request.priority < priority) {
            return true;
        }
    }
    return false;
}

static void mtProxyRemoveQueuedRequestLocked(ConnectionSocket *socket) {
    for (auto &entry : proxyHandshakeEndpoints) {
        auto &queue = entry.second.queuedRequests;
        queue.erase(std::remove_if(queue.begin(), queue.end(), [socket](const MtProxyHandshakeQueuedRequest &request) {
            return request.socket == socket;
        }), queue.end());
    }
}

static bool mtProxyTakeNextQueuedRequestLocked(const std::string &key, MtProxyHandshakeEndpointState &state, int64_t now, MtProxyHandshakeQueuedRequest &request) {
    int32_t limit = mtProxyHandshakeActiveLimit(state, now);
    if (state.activeHandshakes >= limit || state.queuedRequests.empty()) {
        return false;
    }

    int bestIndex = -1;
    for (int i = 0; i < (int) state.queuedRequests.size(); i++) {
        const auto &candidate = state.queuedRequests[i];
        if (MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED && state.cooldownUntil > now && candidate.priority > MT_PROXY_HANDSHAKE_PRIORITY_MEDIA) {
            continue;
        }
        if (bestIndex < 0 || candidate.priority < state.queuedRequests[bestIndex].priority ||
                (candidate.priority == state.queuedRequests[bestIndex].priority && candidate.queuedAt < state.queuedRequests[bestIndex].queuedAt)) {
            bestIndex = i;
        }
    }
    if (bestIndex < 0) {
        return false;
    }

    request = state.queuedRequests[bestIndex];
    state.queuedRequests.erase(state.queuedRequests.begin() + bestIndex);
    state.activeHandshakes++;
    if (LOGS_ENABLED) DEBUG_D("mtproxy_startup admission_dequeue key=%s active=%d queued=%d priority=%d", key.c_str(), state.activeHandshakes, (int) state.queuedRequests.size(), request.priority);
    return true;
}

static void mtProxyApplyFreezeCooldown(MtProxyHandshakeEndpointState &state, int64_t now) {
    if (state.freezePenalty < 3) {
        state.freezePenalty++;
    }
    state.recentSuccesses = 0;
    int64_t base;
    if (state.freezePenalty <= 1) {
        base = 30000;
    } else if (state.freezePenalty == 2) {
        base = 90000;
    } else {
        base = 180000;
    }
    state.cooldownUntil = now + base + secureRandomBounded(15001);
}

static void mtProxyRecordHandshakeSuccess(MtProxyHandshakeEndpointState &state, int64_t now) {
    if (state.recentSuccesses < 4) {
        state.recentSuccesses++;
    }
    state.lastSuccessTime = now;
    if (state.freezePenalty > 0) {
        state.freezePenalty--;
    }
    if (state.freezePenalty == 0) {
        state.cooldownUntil = 0;
    }
}

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

#define MAX_GREASE 8

static BIGNUM *get_y2(BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
    // returns y^2 = x^3 + 486662 * x^2 + x
    BIGNUM *y = BN_dup(x);
    assert(y != NULL);
    BIGNUM *coef = BN_new();
    BN_set_word(coef, 486662);
    BN_mod_add(y, y, coef, mod, big_num_context);
    BN_mod_mul(y, y, x, mod, big_num_context);
    BN_one(coef);
    BN_mod_add(y, y, coef, mod, big_num_context);
    BN_mod_mul(y, y, x, mod, big_num_context);
    BN_clear_free(coef);
    return y;
}

static BIGNUM *get_double_x(BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
    // returns x_2 =(x^2 - 1)^2/(4*y^2)
    BIGNUM *denominator = get_y2(x, mod, big_num_context);
    assert(denominator != NULL);
    BIGNUM *coef = BN_new();
    BN_set_word(coef, 4);
    BN_mod_mul(denominator, denominator, coef, mod, big_num_context);

    BIGNUM *numerator = BN_new();
    assert(numerator != NULL);
    BN_mod_mul(numerator, x, x, mod, big_num_context);
    BN_one(coef);
    BN_mod_sub(numerator, numerator, coef, mod, big_num_context);
    BN_mod_mul(numerator, numerator, numerator, mod, big_num_context);

    BN_mod_inverse(denominator, denominator, mod, big_num_context);
    BN_mod_mul(numerator, numerator, denominator, mod, big_num_context);

    BN_clear_free(coef);
    BN_clear_free(denominator);
    return numerator;
}

static void generate_key_ml_kem_768(unsigned char *key) {
    constexpr uint32_t Q = 3329;
    constexpr int N = 384;

    std::vector<uint32_t> values(N * 2);
    RAND_bytes(reinterpret_cast<unsigned char*>(values.data()),values.size() * sizeof(uint32_t));

    for (int i = 0; i < N; ++i) {
        uint32_t a = values[i * 2]     % Q;
        uint32_t b = values[i * 2 + 1] % Q;

        key[i * 3 + 0] = static_cast<unsigned char>(a & 0xFFu);
        key[i * 3 + 1] = static_cast<unsigned char>((a >> 8) | ((b & 0x0Fu) << 4));
        key[i * 3 + 2] = static_cast<unsigned char>(b >> 4);
    }

    RAND_bytes(key + 1152, 32);
}

static void generate_public_key(unsigned char *key) {
    BIGNUM *mod = NULL;
    BN_hex2bn(&mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    BIGNUM *pow = NULL;
    BN_hex2bn(&pow, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6");
    BN_CTX *big_num_context = BN_CTX_new();
    assert(big_num_context != NULL);

    BIGNUM *x = BN_new();
    while (1) {
        RAND_bytes(key, 32);
        key[31] &= 127;
        BN_bin2bn(key, 32, x);
        assert(x != NULL);
        BN_mod_mul(x, x, x, mod, big_num_context);

        BIGNUM *y = get_y2(x, mod, big_num_context);

        BIGNUM *r = BN_new();
        BN_mod_exp(r, y, pow, mod, big_num_context);
        BN_clear_free(y);
        if (BN_is_one(r)) {
            BN_clear_free(r);
            break;
        }
        BN_clear_free(r);
    }

    int i;
    for (i = 0; i < 3; i++) {
        BIGNUM *x2 = get_double_x(x, mod, big_num_context);
        BN_clear_free(x);
        x = x2;
    }

    int num_size = BN_num_bytes(x);
    assert(num_size <= 32);
    memset(key, '\0', 32 - num_size);
    BN_bn2bin(x, key + (32 - num_size));
    for (i = 0; i < 16; i++) {
        unsigned char t = key[i];
        key[i] = key[31 - i];
        key[31 - i] = t;
    }

    BN_clear_free(x);
    BN_CTX_free(big_num_context);
    BN_clear_free(pow);
    BN_clear_free(mod);
}

class TlsHello {
public:

    TlsHello() {
        RAND_bytes(grease, MAX_GREASE);
        for (int a = 0; a < MAX_GREASE; a++) {
            grease[a] = (uint8_t) ((grease[a] & 0xf0) + 0x0A);
        }
        for (size_t i = 1; i < MAX_GREASE; i += 2) {
            if (grease[i] == grease[i - 1]) {
                grease[i] ^= 0x10;
            }
        }
    }

    struct Op {
        enum class Type {
            String, Random, K, M, P, E, Zero, Domain, Grease, BeginScope, EndScope, Permutation
        };
        Type type;
        size_t length;
        int seed;
        std::string data;
        std::vector<std::vector<Op>> entities;

        static Op string(const char str[], size_t len) {
            Op res;
            res.type = Type::String;
            res.data = std::string(str, len);
            return res;
        }

        static Op random(size_t length) {
            Op res;
            res.type = Type::Random;
            res.length = length;
            return res;
        }

        static Op K() {
            Op res;
            res.type = Type::K;
            res.length = 32;
            return res;
        }

        static Op E() {
            Op res;
            res.type = Type::E;
            return res;
        }

        static Op M() {
            Op res;
            res.type = Type::M;
            return res;
        }

        static Op P() {
            Op res;
            res.type = Type::P;
            return res;
        }

        static Op zero(size_t length) {
            Op res;
            res.type = Type::Zero;
            res.length = length;
            return res;
        }

        static Op domain() {
            Op res;
            res.type = Type::Domain;
            return res;
        }

        static Op grease(int seed) {
            Op res;
            res.type = Type::Grease;
            res.seed = seed;
            return res;
        }

        static Op begin_scope() {
            Op res;
            res.type = Type::BeginScope;
            return res;
        }

        static Op end_scope() {
            Op res;
            res.type = Type::EndScope;
            return res;
        }

        static Op permutation(std::vector<std::vector<Op>> entities) {
            Op res;
            res.type = Type::Permutation;
            res.entities = std::move(entities);
            return res;
        }

    };

    static TlsHello getFirefoxDefault() {
        TlsHello res;
        res.ops = {
                Op::string("\x16\x03\x01", 3),
                Op::begin_scope(),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x03\x03", 2),
                Op::zero(32),
                Op::string("\x20", 1),
                Op::random(32),
                Op::string("\x00\x22", 2),
                Op::grease(0),
                Op::string("\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35", 32),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x00\x00", 2),
                Op::begin_scope(),
                Op::begin_scope(),
                Op::string("\x00", 1),
                Op::begin_scope(),
                Op::domain(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::string("\x00\x17\x00\x00", 4),
                Op::string("\xff\x01\x00\x01\x00", 5),
                Op::string("\x00\x0a\x00\x10\x00\x0e", 6),
                Op::grease(2),
                Op::string("\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01", 12),
                Op::string("\x00\x0b\x00\x02\x01\x00", 6),
                Op::string("\x00\x23\x00\x00", 4),
                Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18),
                Op::string("\x00\x05\x00\x05\x01\x00\x00\x00\x00", 9),
                Op::string("\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03", 14),
                Op::string("\x00\x33\x05\x2f\x05\x2d", 6),
                Op::string("\x11\xec\x04\xc0", 4),
                Op::M(),
                Op::K(),
                Op::string("\x00\x1d\x00\x20", 4),
                Op::K(),
                Op::string("\x00\x17\x00\x41", 4),
                Op::random(65),
                Op::string("\x00\x2b\x00\x07\x06", 5),
                Op::grease(4),
                Op::string("\x03\x04\x03\x03", 4),
                Op::string("\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01", 28),
                Op::string("\x00\x2d\x00\x02\x01\x01", 6),
                Op::string("\x00\x1c\x00\x02\x40\x01", 6),
                Op::string("\x00\x1b\x00\x07\x06\x00\x01\x00\x02\x00\x03", 11),
                Op::string("\xfe\x0d\x01\x19", 4),
                Op::string("\x00\x00\x01\x00\x01", 5),
                Op::random(1),
                Op::string("\x00\x20", 2),
                Op::K(),
                Op::string("\x00\xef", 2),
                Op::random(239),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope()
        };
        return res;
    }

    static TlsHello getDefault() {
        TlsHello res;
        res.ops = {
                    Op::string("\x16\x03\x01", 3),
                    Op::begin_scope(),
                    Op::string("\x01\x00", 2),
                    Op::begin_scope(),
                    Op::string("\x03\x03", 2),
                    Op::zero(32),
                    Op::string("\x20", 1),
                    Op::random(32),
                    Op::string("\x00\x20", 2),
                    Op::grease(0),
                    Op::string("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00", 32),
                    Op::begin_scope(),
                    Op::grease(2),
                    Op::string("\x00\x00", 2),
                    Op::permutation({
                        {
                            Op::string("\x00\x00", 2),
                            Op::begin_scope(),
                            Op::begin_scope(),
                            Op::string("\x00", 1),
                            Op::begin_scope(),
                            Op::domain(),
                            Op::end_scope(),
                            Op::end_scope(),
                            Op::end_scope()
                        },
                        { Op::string("\x00\x05\x00\x05\x01\x00\x00\x00\x00",9) },
                        {
                            Op::string("\x00\x0a\x00\x0c\x00\x0a", 6),
                            Op::grease(4),
                            Op::string("\x11\xec\x00\x1d\x00\x17\x00\x18", 8)
                        },
                        { Op::string("\x00\x0b\x00\x02\x01\x00", 6) },
                        { Op::string("\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01",22) },
                        { Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18) },
                        { Op::string("\x00\x12\x00\x00", 4) },
                        { Op::string("\x00\x17\x00\x00", 4) },
                        { Op::string("\x00\x1b\x00\x03\x02\x00\x02", 7) },
                        { Op::string("\x00\x23\x00\x00", 4) },
                        {
                            Op::string("\x00\x2b\x00\x07\x06", 5),
                            Op::grease(6),
                            Op::string("\x03\x04\x03\x03", 4)
                        },
                        { Op::string("\x00\x2d\x00\x02\x01\x01", 6) },
                        {
                            Op::string("\x00\x33\x04\xef\x04\xed", 6),
                            Op::grease(4),
                            Op::string("\x00\x01\x00\x11\xec\x04\xc0", 7),
                            Op::M(),
                            Op::K(),
                            Op::string("\x00\x1d\x00\x20", 4),
                            Op::K(),
                        },
                        { Op::string("\x44\xcd\x00\x05\x00\x03\x02\x68\x32", 9) },
                        {
                            Op::string("\xfe\x0d", 2),
                            Op::begin_scope(),
                            Op::string("\x00\x00\x01\x00\x01", 5),
                            Op::random(1),
                            Op::string("\x00\x20", 2),
                            Op::K(),
                            Op::begin_scope(),
                            Op::E(),
                            Op::end_scope(),
                            Op::end_scope()
                        },
                        { Op::string("\xff\x01\x00\x01\x00", 5) }
                    }),
                    Op::grease(3),
                    Op::string("\x00\x01\x00", 3),
                    Op::P(),
                    Op::end_scope(),
                    Op::end_scope(),
                    Op::end_scope()
        };
        return res;
    }

    static TlsHello getAndroidChromeDefault() {
        return getDefault();
    }

    static TlsHello getFirefoxAndroidDefault() {
        TlsHello res;
        res.ops = {
                Op::string("\x16\x03\x01", 3),
                Op::begin_scope(),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x03\x03", 2),
                Op::zero(32),
                Op::string("\x20", 1),
                Op::random(32),
                Op::string("\x00\x22", 2),
                Op::string("\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35", 34),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x00\x00", 2),
                Op::begin_scope(),
                Op::begin_scope(),
                Op::string("\x00", 1),
                Op::begin_scope(),
                Op::domain(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::string("\x00\x17\x00\x00", 4),
                Op::string("\xff\x01\x00\x01\x00", 5),
                Op::string("\x00\x0a\x00\x10\x00\x0e\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01", 20),
                Op::string("\x00\x0b\x00\x02\x01\x00", 6),
                Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18),
                Op::string("\x00\x05\x00\x05\x01\x00\x00\x00\x00", 9),
                Op::string("\x00\x22\x00\x0a\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03", 14),
                Op::string("\x00\x33\x05\x2f\x05\x2d", 6),
                Op::string("\x11\xec\x04\xc0", 4),
                Op::M(),
                Op::K(),
                Op::string("\x00\x1d\x00\x20", 4),
                Op::K(),
                Op::string("\x00\x17\x00\x41", 4),
                Op::random(65),
                Op::string("\x00\x2b\x00\x05\x04\x03\x04\x03\x03", 9),
                Op::string("\x00\x0d\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01", 28),
                Op::string("\x00\x2d\x00\x02\x01\x01", 6),
                Op::string("\x00\x1c\x00\x02\x40\x01", 6),
                Op::string("\x00\x1b\x00\x07\x06\x00\x01\x00\x02\x00\x03", 11),
                Op::string("\xfe\x0d\x01\xb9", 4),
                Op::string("\x00\x00\x01\x00\x01", 5),
                Op::random(1),
                Op::string("\x00\x20", 2),
                Op::K(),
                Op::string("\x01\x8f", 2),
                Op::random(399),
                Op::string("\x00\x29", 2),
                Op::begin_scope(),
                Op::string("\x00\x6f\x00\x69", 4),
                Op::random(105),
                Op::random(4),
                Op::string("\x00\x21\x20", 3),
                Op::random(32),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope()
        };
        return res;
    }

    static TlsHello getAndroidOkHttpDefault() {
        TlsHello res;
        res.ops = {
                Op::string("\x16\x03\x01", 3),
                Op::begin_scope(),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x03\x03", 2),
                Op::zero(32),
                Op::string("\x20", 1),
                Op::random(32),
                Op::string("\x00\x20", 2),
                Op::grease(0),
                Op::string("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00", 32),
                Op::begin_scope(),
                Op::grease(2),
                Op::string("\x00\x00", 2),
                Op::string("\x00\x00", 2),
                Op::begin_scope(),
                Op::begin_scope(),
                Op::string("\x00", 1),
                Op::begin_scope(),
                Op::domain(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::string("\x00\x0a\x00\x0a\x00\x08", 6),
                Op::grease(4),
                Op::string("\x00\x1d\x00\x17\x00\x18", 6),
                Op::string("\x00\x0b\x00\x02\x01\x00", 6),
                Op::string("\x00\x0d\x00\x0e\x00\x0c\x04\x03\x05\x03\x04\x01\x05\x01\x02\x01\x02\x03", 18),
                Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18),
                Op::string("\x00\x2b\x00\x07\x06", 5),
                Op::grease(6),
                Op::string("\x03\x04\x03\x03", 4),
                Op::string("\x00\x2d\x00\x02\x01\x01", 6),
                Op::string("\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20", 10),
                Op::K(),
                Op::grease(3),
                Op::string("\x00\x01\x00", 3),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope()
        };
        return res;
    }

    static TlsHello getYandexDefault() {
        TlsHello res;
        res.ops = {
                Op::string("\x16\x03\x01", 3),
                Op::begin_scope(),
                Op::string("\x01\x00", 2),
                Op::begin_scope(),
                Op::string("\x03\x03", 2),
                Op::zero(32),
                Op::string("\x20", 1),
                Op::random(32),
                Op::string("\x00\x20", 2),
                Op::grease(0),
                Op::string("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00", 32),
                Op::begin_scope(),
                Op::grease(2),
                Op::string("\x00\x00", 2),
                Op::string("\x00\x17\x00\x00", 4),
                Op::string("\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01", 22),
                Op::string("\x00\x00", 2),
                Op::begin_scope(),
                Op::begin_scope(),
                Op::string("\x00", 1),
                Op::begin_scope(),
                Op::domain(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::string("\x00\x0b\x00\x02\x01\x00", 6),
                Op::string("\x00\x2d\x00\x02\x01\x01", 6),
                Op::string("\x00\x1b\x00\x03\x02\x00\x02", 7),
                Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18),
                Op::string("\xff\x01\x00\x01\x00", 5),
                Op::string("\x00\x23\x00\x00", 4),
                Op::string("\x00\x2b\x00\x07\x06", 5),
                Op::grease(6),
                Op::string("\x03\x04\x03\x03", 4),
                Op::string("\x00\x12\x00\x00", 4),
                Op::string("\x00\x05\x00\x05\x01\x00\x00\x00\x00", 9),
                Op::string("\x44\xcd\x00\x05\x00\x03\x02\x68\x32", 9),
                Op::string("\x00\x0a\x00\x0c\x00\x0a", 6),
                Op::grease(4),
                Op::string("\x11\xec\x00\x1d\x00\x17\x00\x18", 8),
                Op::string("\xfe\x0d", 2),
                Op::begin_scope(),
                Op::string("\x00\x00\x01\x00\x01", 5),
                Op::random(1),
                Op::string("\x00\x20", 2),
                Op::K(),
                Op::begin_scope(),
                Op::E(),
                Op::end_scope(),
                Op::end_scope(),
                Op::string("\x00\x33\x04\xef\x04\xed", 6),
                Op::grease(4),
                Op::string("\x00\x01\x00\x11\xec\x04\xc0", 7),
                Op::M(),
                Op::K(),
                Op::string("\x00\x1d\x00\x20", 4),
                Op::K(),
                Op::grease(3),
                Op::string("\x00\x00", 2),
                Op::string("\x00\x29", 2),
                Op::begin_scope(),
                Op::string("\x00\x6f\x00\x69", 4),
                Op::random(105),
                Op::random(4),
                Op::string("\x00\x21\x20", 3),
                Op::random(32),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope()
        };
        return res;
    }

    uint32_t writeToBuffer(uint8_t *data) {
        uint32_t offset = 0;
        for (auto op : ops) {
            writeOp(op, data, offset);
        }
        return offset;
    }

    void setDomain(std::string value) {
        domain = std::move(value);
    }

private:
    std::vector<Op> ops;
    uint8_t grease[MAX_GREASE];
    std::vector<size_t> scopeOffset;
    std::string domain;

    void writeOp(const TlsHello::Op &op, uint8_t *data, uint32_t &offset) {
        using Type = TlsHello::Op::Type;
        switch (op.type) {
            case Type::String:
                memcpy(data + offset, op.data.data(), op.data.size());
                offset += op.data.size();
                break;
            case Type::Random:
                RAND_bytes(data + offset, (size_t) op.length);
                offset += op.length;
                break;
            case Type::K:
                generate_public_key(data + offset);
                offset += op.length;
                break;
            case Type::M:
                generate_key_ml_kem_768(data + offset);
                offset += 1184;
                break;
            case Type::Zero:
                std::memset(data + offset, 0, op.length);
                offset += op.length;
                break;
            case Type::Domain: {
                size_t size = domain.size();
                if (size > 253) {
                    size = 253;
                }
                memcpy(data + offset, domain.data(), size);
                offset += size;
                break;
            }
            case Type::Grease: {
                data[offset] = grease[op.seed];
                data[offset + 1] = grease[op.seed];
                offset += 2;
                break;
            }
            case Type::BeginScope:
                scopeOffset.push_back(offset);
                offset += 2;
                break;
            case Type::EndScope: {
                auto begin_offset = scopeOffset.back();
                scopeOffset.pop_back();
                size_t size = offset - begin_offset - 2;
                data[begin_offset] = static_cast<uint8_t>((size >> 8) & 0xff);
                data[begin_offset + 1] = static_cast<uint8_t>(size & 0xff);
                break;
            }
            case Type::E: {
                size_t r = secureRandomBounded(4);
                size_t length = (r == 0 ? 144 :
                                (r == 1 ? 176 :
                                (r == 2 ? 208 : 240)));
                RAND_bytes(data + offset, (size_t) length);
                offset += length;
                break;
            }
            case Type::P: {
                auto length = offset;
                // Randomized padding target instead of a fixed 513-byte ClientHello: a single
                // fixed length is itself a DPI signature (the legacy faketls 517-byte record).
                // Dormant for profiles whose body already exceeds the target (e.g. ML-KEM Chrome).
                uint32_t target = 512 + secureRandomBounded(257); // 512..768
                if (length <= target) {
                    writeOp(Op::string("\x00\x15", 2), data, offset);
                    writeOp(Op::begin_scope(), data, offset);
                    writeOp(Op::zero(target - length), data, offset);
                    writeOp(Op::end_scope(), data, offset);
                }
                break;
            }
            case Type::Permutation: {
                std::vector<std::vector<Op>> list = {};
                for (const auto &part : op.entities) {
                    list.push_back(part);
                }
                size_t size = list.size();
                for (int i = 0; i < size - 1; i++) {
                    int j = i + (int) secureRandomBounded((uint32_t) (size - i));
                    if (i != j) {
                        std::swap(list[i], list[j]);
                    }
                }
                for (const auto &part : list) {
                    for (const auto &op_local: part) {
                        writeOp(op_local, data, offset);
                    }
                }
                break;
            }
        }
    }
};

static int32_t normalizeMtProxyTlsProfile(int32_t profile) {
    if (profile >= MT_PROXY_TLS_PROFILE_FIREFOX && profile <= MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP) {
        return profile;
    }
    return MT_PROXY_TLS_PROFILE_ANDROID_CHROME;
}

static int32_t normalizeMtProxyClientHelloFragmentation(int32_t mode) {
    return mode == MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT ? MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT : MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
}

static const char *mtProxyTlsProfileName(int32_t profile) {
    switch (normalizeMtProxyTlsProfile(profile)) {
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
        default:
            return "android_chrome";
    }
}

static TlsHello selectMtProxyTlsHello(int32_t profile) {
    switch (normalizeMtProxyTlsProfile(profile)) {
        case MT_PROXY_TLS_PROFILE_FIREFOX:
            return TlsHello::getFirefoxDefault();
        case MT_PROXY_TLS_PROFILE_YANDEX:
            return TlsHello::getYandexDefault();
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return TlsHello::getFirefoxAndroidDefault();
        case MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP:
            return TlsHello::getAndroidOkHttpDefault();
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
        default:
            return TlsHello::getAndroidChromeDefault();
    }
}

static bool isGreaseValue(uint16_t value) {
    uint8_t high = (uint8_t) ((value >> 8) & 0xff);
    uint8_t low = (uint8_t) (value & 0xff);
    return high == low && (low & 0x0f) == 0x0a;
}

static bool validateServerCompatibleHello(const uint8_t *data, uint32_t size, const std::string &domain, const char *profileName) {
    if (size < 100 || size > 4096) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s invalid hello size=%u", profileName, size);
        return false;
    }
    if (data[0] != 0x16 || data[1] != 0x03 || data[2] != 0x01 || data[5] != 0x01 || data[9] != 0x03 || data[10] != 0x03) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s invalid hello prefix", profileName);
        return false;
    }
    uint32_t recordLength = ((uint32_t) data[3] << 8) | data[4];
    uint32_t handshakeLength = ((uint32_t) data[6] << 16) | ((uint32_t) data[7] << 8) | data[8];
    if (recordLength + 5 != size || handshakeLength + 9 != size) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s invalid hello lengths record=%u handshake=%u size=%u", profileName, recordLength, handshakeLength, size);
        return false;
    }

    const uint32_t cipherSuitesOffset = 76;
    if (size <= cipherSuitesOffset + 2) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s too short for cipher suites", profileName);
        return false;
    }
    uint32_t cipherSuitesLength = ((uint32_t) data[cipherSuitesOffset] << 8) | data[cipherSuitesOffset + 1];
    uint32_t cipherSuitesBegin = cipherSuitesOffset + 2;
    uint32_t cipherSuitesEnd = cipherSuitesBegin + cipherSuitesLength;
    if (cipherSuitesLength < 2 || (cipherSuitesLength % 2) != 0 || cipherSuitesEnd > size) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s invalid cipher suites length=%u", profileName, cipherSuitesLength);
        return false;
    }

    uint16_t firstCipher = 0;
    for (uint32_t offset = cipherSuitesBegin; offset + 1 < cipherSuitesEnd; offset += 2) {
        uint16_t cipher = ((uint16_t) data[offset] << 8) | data[offset + 1];
        if (!isGreaseValue(cipher)) {
            firstCipher = cipher; // first non-GREASE cipher must be TLS_AES_* for MTProxy server compatibility.
            break;
        }
    }
    if (firstCipher != 0x1301 && firstCipher != 0x1302 && firstCipher != 0x1303) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s invalid first cipher=0x%04x", profileName, firstCipher);
        return false;
    }

    size_t domainSize = std::min(domain.size(), (size_t) 253);
    if (domainSize == 0 || std::search(data, data + size, (const uint8_t *) domain.data(), (const uint8_t *) domain.data() + domainSize) == data + size) {
        if (LOGS_ENABLED) DEBUG_E("mtproxy_startup profile %s missing SNI domain size=%zu", profileName, domainSize);
        return false;
    }
    return true;
}

ConnectionSocket::ConnectionSocket(int32_t instance) {
    instanceNum = instance;
    outgoingByteStream = new ByteStream();
    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    eventObject = new EventObject(this, EventObjectTypeConnection);
}

ConnectionSocket::~ConnectionSocket() {
    cancelProxyHandshakeAdmission();
    clearPendingClientHello();
    clearPendingTlsFrame();
    if (proxyHandshakeAdmissionTimer != nullptr) {
        delete proxyHandshakeAdmissionTimer;
        proxyHandshakeAdmissionTimer = nullptr;
    }
    if (outgoingByteStream != nullptr) {
        delete outgoingByteStream;
        outgoingByteStream = nullptr;
    }
    if (eventObject != nullptr) {
        delete eventObject;
        eventObject = nullptr;
    }
    if (tempBuffer != nullptr) {
        delete tempBuffer;
        tempBuffer = nullptr;
    }
    if (tlsBuffer != nullptr) {
        tlsBuffer->reuse();
        tlsBuffer = nullptr;
    }
}

bool ConnectionSocket::scheduleProxyHandshakeAdmissionIfNeeded(bool ipv6) {
    if (proxyAuthState < 10 || socketFd < 0) {
        return false;
    }
    if (!MT_PROXY_HANDSHAKE_ADMISSION_ENABLED) {
        if (proxyHandshakeAdmissionKey.empty()) {
            proxyHandshakeAdmissionKey = currentAddress + ":" + std::to_string((unsigned int) currentPort) + ":" + currentSecretDomain;
        }
        proxyHandshakeAdmissionQueued = false;
        proxyHandshakeAdmissionActive = true;
        proxyHandshakeAdmissionReady = false;
        proxyHandshakeAdmissionIpv6 = ipv6;
        proxyHandshakeAdmissionStartTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
        proxyHandshakeClientHelloSentTime = 0;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_disabled key=%s priority=%d", this, proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority);
        return false;
    }
    if (proxyHandshakeAdmissionPriority == MT_PROXY_HANDSHAKE_PRIORITY_BYPASS) {
        return false;
    }
    if (proxyHandshakeAdmissionReady) {
        proxyHandshakeAdmissionReady = false;
        return false;
    }
    if (proxyHandshakeAdmissionKey.empty()) {
        proxyHandshakeAdmissionKey = currentAddress + ":" + std::to_string((unsigned int) currentPort) + ":" + currentSecretDomain;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    uint32_t delay = 0;
    bool shouldQueue = false;
    pthread_mutex_lock(&proxyHandshakeSchedulerMutex);
    mtProxyRemoveQueuedRequestLocked(this);
    MtProxyHandshakeEndpointState &state = proxyHandshakeEndpoints[proxyHandshakeAdmissionKey];
    int32_t limit = mtProxyHandshakeActiveLimit(state, now);
    bool cooldownBlocks = MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED && state.cooldownUntil > now && proxyHandshakeAdmissionPriority > MT_PROXY_HANDSHAKE_PRIORITY_MEDIA;
    if (cooldownBlocks || state.activeHandshakes >= limit || mtProxyHandshakeHasHigherPriorityQueued(state, proxyHandshakeAdmissionPriority)) {
        MtProxyHandshakeQueuedRequest request;
        request.socket = this;
        request.generation = proxyHandshakeAdmissionGeneration;
        request.priority = proxyHandshakeAdmissionPriority;
        request.queuedAt = now;
        request.ipv6 = ipv6;
        state.queuedRequests.push_back(request);
        shouldQueue = true;
        delay = mtProxyHandshakeRetryDelay(now, state.cooldownUntil, proxyHandshakeAdmissionPriority);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_queue key=%s priority=%d active=%d limit=%d queued=%d cooldown_ms=%ld retry=%u", this, proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority, state.activeHandshakes, limit, (int) state.queuedRequests.size(), (long) std::max<int64_t>(0, state.cooldownUntil - now), delay);
    } else {
        state.activeHandshakes++;
        proxyHandshakeAdmissionActive = true;
        proxyHandshakeAdmissionQueued = false;
        proxyHandshakeAdmissionStartTime = now;
        proxyHandshakeClientHelloSentTime = 0;
        if (state.activeHandshakes > 1) {
            delay = mtProxyHandshakeGrantDelay();
        }
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_grant key=%s priority=%d active=%d limit=%d delay=%u successes=%d", this, proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority, state.activeHandshakes, limit, delay, state.recentSuccesses);
    }
    pthread_mutex_unlock(&proxyHandshakeSchedulerMutex);

    if (shouldQueue) {
        proxyHandshakeAdmissionQueued = true;
        scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_ADMISSION, ipv6);
        return true;
    }
    if (delay == 0) {
        return false;
    }

    proxyHandshakeAdmissionReady = true;
    scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_ADMISSION, ipv6);
    return true;
}

void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer(uint32_t delay, int32_t mode, bool ipv6) {
    if (proxyHandshakeAdmissionTimer == nullptr) {
        proxyHandshakeAdmissionTimer = new Timer(instanceNum, [this] {
            if (proxyHandshakeAdmissionTimer != nullptr) {
                proxyHandshakeAdmissionTimer->stop();
            }
            int32_t mode = proxyHandshakeAdmissionTimerMode;
            proxyHandshakeAdmissionTimerMode = 0;
            if (socketFd < 0) {
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_FREEZE) {
                markProxyHandshakeFreezeIfNeeded();
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_SERVER_HELLO) {
                markProxyServerHelloHmacTimeoutIfNeeded();
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_CLIENT_HELLO_FRAGMENT) {
                adjustWriteOp();
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_ADMISSION) {
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_timer_fire generation=%u ready=%d queued=%d active=%d", this, proxyHandshakeAdmissionGeneration, proxyHandshakeAdmissionReady ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0);
                openConnectionInternal(delayedIpv6);
            }
        });
    }

    proxyHandshakeAdmissionTimer->stop();
    proxyHandshakeAdmissionIpv6 = ipv6;
    proxyHandshakeAdmissionTimerMode = mode;
    proxyHandshakeAdmissionTimer->setTimeout(delay, false);
    proxyHandshakeAdmissionTimer->start();
}

void ConnectionSocket::grantProxyHandshakeAdmission(bool ipv6, uint32_t generation, uint32_t delay, const char *reason) {
    if (generation != proxyHandshakeAdmissionGeneration || socketFd < 0 || proxyAuthState < 10) {
        return;
    }
    proxyHandshakeAdmissionQueued = false;
    proxyHandshakeAdmissionActive = true;
    proxyHandshakeAdmissionReady = true;
    proxyHandshakeAdmissionStartTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    proxyHandshakeClientHelloSentTime = 0;
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_grant_queued reason=%s key=%s priority=%d delay=%u", this, reason, proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority, delay);
    scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_ADMISSION, ipv6);
}

void ConnectionSocket::cancelProxyHandshakeAdmission() {
    if (proxyHandshakeAdmissionActive) {
        releaseProxyHandshakeAdmission(false, "cancel");
    }
    pthread_mutex_lock(&proxyHandshakeSchedulerMutex);
    mtProxyRemoveQueuedRequestLocked(this);
    pthread_mutex_unlock(&proxyHandshakeSchedulerMutex);
    proxyHandshakeAdmissionQueued = false;
    proxyHandshakeAdmissionActive = false;
    proxyHandshakeAdmissionReady = false;
    proxyHandshakeAdmissionIpv6 = false;
    proxyHandshakeAdmissionTimerMode = 0;
    proxyHandshakeAdmissionGeneration++;
    proxyHandshakeAdmissionStartTime = 0;
    proxyHandshakeClientHelloSentTime = 0;
    proxyHandshakeAdmissionKey.clear();
    if (proxyHandshakeAdmissionTimer != nullptr) {
        proxyHandshakeAdmissionTimer->stop();
    }
}

void ConnectionSocket::releaseProxyHandshakeAdmission(bool succeeded, const char *reason) {
    if (proxyHandshakeAdmissionKey.empty()) {
        proxyHandshakeAdmissionActive = false;
        return;
    }

    MtProxyHandshakeQueuedRequest nextRequest;
    bool hasNextRequest = false;
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    pthread_mutex_lock(&proxyHandshakeSchedulerMutex);
    MtProxyHandshakeEndpointState &state = proxyHandshakeEndpoints[proxyHandshakeAdmissionKey];
    mtProxyRemoveQueuedRequestLocked(this);
    if (proxyHandshakeAdmissionActive && state.activeHandshakes > 0) {
        state.activeHandshakes--;
    }
    int64_t clientHelloElapsed = proxyHandshakeClientHelloSentTime > 0 ? now - proxyHandshakeClientHelloSentTime : 0;
    bool shouldApplyFreezeCooldown = proxyHandshakeAdmissionActive && proxyHandshakeClientHelloSentTime > 0 && clientHelloElapsed >= MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS;
    if (succeeded) {
        mtProxyRecordHandshakeSuccess(state, now);
    } else if (shouldApplyFreezeCooldown && MT_PROXY_HANDSHAKE_FREEZE_COOLDOWN_ENABLED) {
        mtProxyApplyFreezeCooldown(state, now);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_freeze_cooldown reason=%s key=%s penalty=%d cooldown_ms=%ld", this, reason, proxyHandshakeAdmissionKey.c_str(), state.freezePenalty, (long) std::max<int64_t>(0, state.cooldownUntil - now));
    } else if (shouldApplyFreezeCooldown) {
        state.recentSuccesses = 0;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_freeze_observed reason=%s key=%s cooldown=disabled", this, reason, proxyHandshakeAdmissionKey.c_str());
    }
    hasNextRequest = mtProxyTakeNextQueuedRequestLocked(proxyHandshakeAdmissionKey, state, now, nextRequest);
    pthread_mutex_unlock(&proxyHandshakeSchedulerMutex);

    proxyHandshakeAdmissionQueued = false;
    proxyHandshakeAdmissionActive = false;
    proxyHandshakeAdmissionReady = false;
    proxyHandshakeAdmissionStartTime = 0;
    proxyHandshakeClientHelloSentTime = 0;
    proxyHandshakeAdmissionTimerMode = 0;
    if (proxyHandshakeAdmissionTimer != nullptr) {
        proxyHandshakeAdmissionTimer->stop();
    }

    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_release reason=%s success=%d key=%s next=%d", this, reason, succeeded ? 1 : 0, proxyHandshakeAdmissionKey.c_str(), hasNextRequest ? 1 : 0);
    if (hasNextRequest && nextRequest.socket != nullptr) {
        nextRequest.socket->grantProxyHandshakeAdmission(nextRequest.ipv6, nextRequest.generation, mtProxyHandshakeGrantDelay(), reason);
    }
}

void ConnectionSocket::markProxyHandshakeClientHelloSent() {
    if (!proxyHandshakeAdmissionActive || proxyHandshakeAdmissionKey.empty()) {
        return;
    }
    proxyHandshakeClientHelloSentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    scheduleProxyHandshakeAdmissionTimer((uint32_t) MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS, MT_PROXY_HANDSHAKE_TIMER_FREEZE, proxyHandshakeAdmissionIpv6);
}

void ConnectionSocket::markProxyHandshakeFreezeIfNeeded() {
    if (!proxyHandshakeAdmissionActive || proxyHandshakeClientHelloSentTime == 0 || proxyAuthState != 11) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    int64_t elapsed = now - proxyHandshakeClientHelloSentTime;
    if (elapsed >= MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_freeze_detected key=%s elapsed=%ld", this, proxyHandshakeAdmissionKey.c_str(), (long) elapsed);
        releaseProxyHandshakeAdmission(false, "freeze_timeout");
        if (MT_PROXY_HANDSHAKE_CLOSE_ON_FREEZE_ENABLED) {
            if (serverHelloHmacMismatchObserved) {
                proxyCheckDiagnostic = "server_hello_hmac_mismatch";
                tlsHashMismatch = true;
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_timeout bytes=%zu", this, bytesRead);
            } else {
                proxyCheckDiagnostic = "client_hello_sent_no_server_hello";
            }
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_timeout_close elapsed=%ld", this, (long) elapsed);
            closeSocket(1, ETIMEDOUT);
        }
    }
}

void ConnectionSocket::markProxyServerHelloHmacTimeoutIfNeeded() {
    if (!serverHelloHmacMismatchObserved || serverHelloHmacMismatchTime == 0 || proxyAuthState != 11) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    int64_t elapsed = now - serverHelloHmacMismatchTime;
    if (elapsed >= MT_PROXY_SERVER_HELLO_HMAC_WAIT_MS) {
        proxyCheckDiagnostic = "server_hello_hmac_mismatch";
        tlsHashMismatch = true;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_timeout bytes=%zu elapsed=%ld", this, bytesRead, (long) elapsed);
        closeSocket(1, ETIMEDOUT);
    }
}

const char *ConnectionSocket::getProxyCheckDiagnostic() {
    return proxyCheckDiagnostic.empty() ? "unknown_fail" : proxyCheckDiagnostic.c_str();
}

void ConnectionSocket::clearPendingClientHello() {
    if (pendingClientHello != nullptr) {
        delete pendingClientHello;
        pendingClientHello = nullptr;
    }
    pendingClientHelloSize = 0;
    pendingClientHelloOffset = 0;
    pendingClientHelloFragmentTarget = 0;
    pendingClientHelloFragmentIndex = 0;
    pendingClientHelloFragmentCount = 0;
    pendingClientHelloNextWriteTime = 0;
}

bool ConnectionSocket::buildPendingClientHello(uint32_t size) {
    if (pendingClientHello != nullptr || size == 0) {
        return false;
    }
    pendingClientHelloSize = size;
    pendingClientHelloOffset = 0;
    pendingClientHello = new ByteArray(size);
    std::memcpy(pendingClientHello->bytes, tempBuffer->bytes, size);
    if (currentClientHelloFragmentation == MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT && size >= 384) {
        uint32_t maxFirst = std::min<uint32_t>(768, size - 96);
        uint32_t minFirst = std::min<uint32_t>(224, maxFirst);
        uint32_t range = maxFirst > minFirst ? maxFirst - minFirst + 1 : 1;
        pendingClientHelloFragmentTarget = minFirst + secureRandomBounded(range);
        pendingClientHelloFragmentCount = 2;
        pendingClientHelloFragmentIndex = 0;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup client_hello_fragment_plan mode=soft total=%u first=%u fragments=%u", this, size, pendingClientHelloFragmentTarget, pendingClientHelloFragmentCount);
    }
    return true;
}

bool ConnectionSocket::sendPendingClientHelloFragment(uint32_t limit) {
    while (pendingClientHello != nullptr && pendingClientHelloOffset < limit) {
        ssize_t sentLength = send(socketFd, pendingClientHello->bytes + pendingClientHelloOffset, limit - pendingClientHelloOffset, 0);
        if (sentLength < 0) {
            int err = errno;
            if (err == EINTR) {
                continue;
            }
            if (err == EAGAIN || err == EWOULDBLOCK) {
                adjustWriteOp();
                return true;
            }
            if (LOGS_ENABLED) DEBUG_E("connection(%p) ClientHello pending send failed errno=%d", this, err);
            closeSocket(1, -1);
            return false;
        }
        if (sentLength == 0) {
            adjustWriteOp();
            return true;
        }
        pendingClientHelloOffset += (uint32_t) sentLength;
        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
        if (pendingClientHelloOffset < pendingClientHelloSize && LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_startup client_hello_send_progress bytes=%u expected=%u", this, pendingClientHelloOffset, pendingClientHelloSize);
        }
    }
    return true;
}

bool ConnectionSocket::sendPendingClientHello() {
    while (pendingClientHello != nullptr && pendingClientHelloOffset < pendingClientHelloSize) {
        if (pendingClientHelloFragmentTarget > pendingClientHelloOffset && pendingClientHelloFragmentTarget < pendingClientHelloSize) {
            if (!sendPendingClientHelloFragment(pendingClientHelloFragmentTarget)) {
                return false;
            }
            if (pendingClientHelloOffset < pendingClientHelloFragmentTarget) {
                return true;
            }
            uint32_t delay = 35 + secureRandomBounded(66);
            pendingClientHelloNextWriteTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis() + delay;
            pendingClientHelloFragmentIndex++;
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup client_hello_fragment mode=soft index=%u offset=%u total=%u next_delay=%u", this, pendingClientHelloFragmentIndex, pendingClientHelloOffset, pendingClientHelloSize, delay);
            pendingClientHelloFragmentTarget = 0;
            scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_CLIENT_HELLO_FRAGMENT, proxyHandshakeAdmissionIpv6);
            return true;
        }

        if (pendingClientHelloNextWriteTime > 0) {
            int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
            if (now < pendingClientHelloNextWriteTime) {
                return true;
            }
            pendingClientHelloNextWriteTime = 0;
        }

        if (!sendPendingClientHelloFragment(pendingClientHelloSize)) {
            return false;
        }
    }
    return true;
}

void ConnectionSocket::clearPendingTlsFrame() {
    if (pendingTlsFrame != nullptr) {
        delete pendingTlsFrame;
        pendingTlsFrame = nullptr;
    }
    pendingTlsFrameSize = 0;
    pendingTlsFrameOffset = 0;
    pendingTlsPayloadSize = 0;
}

bool ConnectionSocket::buildPendingTlsFrame(NativeByteBuffer *buffer, uint32_t remaining) {
    if (pendingTlsFrame != nullptr || buffer == nullptr || remaining == 0) {
        return false;
    }
    if (remaining > 2878) {
        remaining = 2878;
    }
    size_t headersSize = 0;
    if (tlsState == 1) {
        static std::string header1 = std::string("\x14\x03\x03\x00\x01\x01", 6);
        std::memcpy(tempBuffer->bytes, header1.data(), header1.size());
        headersSize += header1.size();
        tlsState = 2;
    }
    static std::string header2 = std::string("\x17\x03\x03", 3);
    std::memcpy(tempBuffer->bytes + headersSize, header2.data(), header2.size());
    headersSize += header2.size();

    tempBuffer->bytes[headersSize] = static_cast<uint8_t>((remaining >> 8) & 0xff);
    tempBuffer->bytes[headersSize + 1] = static_cast<uint8_t>(remaining & 0xff);
    headersSize += 2;

    std::memcpy(tempBuffer->bytes + headersSize, buffer->bytes(), remaining);

    pendingTlsFrameSize = (uint32_t) headersSize + remaining;
    pendingTlsFrameOffset = 0;
    pendingTlsPayloadSize = remaining;
    pendingTlsFrame = new ByteArray(pendingTlsFrameSize);
    std::memcpy(pendingTlsFrame->bytes, tempBuffer->bytes, pendingTlsFrameSize);
    return true;
}

bool ConnectionSocket::sendPendingTlsFrame() {
    while (pendingTlsFrame != nullptr && pendingTlsFrameOffset < pendingTlsFrameSize) {
        ssize_t sentLength = send(socketFd, pendingTlsFrame->bytes + pendingTlsFrameOffset, pendingTlsFrameSize - pendingTlsFrameOffset, 0);
        if (sentLength < 0) {
            int err = errno;
            if (err == EINTR) {
                continue;
            }
            if (err == EAGAIN || err == EWOULDBLOCK) {
                adjustWriteOp();
                return true;
            }
            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS pending send failed errno=%d", this, err);
            closeSocket(1, -1);
            return false;
        }
        if (sentLength == 0) {
            adjustWriteOp();
            return true;
        }
        pendingTlsFrameOffset += (uint32_t) sentLength;
        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
        if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
            ConnectionsManager::getInstance(instanceNum).delegate->onBytesSent((int32_t) sentLength, currentNetworkType, instanceNum);
        }
    }

    if (pendingTlsFrame != nullptr) {
        if (tlsState != 0 && !mtproxyFirstTlsFrameSentLogged) {
            mtproxyFirstTlsFrameSentLogged = true;
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_tls_app_sent payload=%u frame=%u", this, pendingTlsPayloadSize, pendingTlsFrameSize);
        }
        outgoingByteStream->discard(pendingTlsPayloadSize);
        clearPendingTlsFrame();
        adjustWriteOp();
    }
    return true;
}

void ConnectionSocket::openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType) {
    cancelProxyHandshakeAdmission();
    clearPendingClientHello();
    clearPendingTlsFrame();
    currentNetworkType = networkType;
    isIpv6 = ipv6;
    currentAddress = address;
    currentPort = port;
    waitingForHostResolve = "";
    adjustWriteOpAfterResolve = false;
    currentSecret = "";
    currentSecretDomain = "";
    currentSecretKind = "none";
    currentSecretIsFakeTls = false;
    currentProxyTlsProfile = normalizeMtProxyTlsProfile(MT_PROXY_TLS_PROFILE_ANDROID_CHROME);
    currentClientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    proxyCheckDiagnostic = "tcp_not_connected";
    proxyHandshakeAdmissionKey = "";
    tlsState = 0;
    mtproxySocketConnectedLogged = false;
    mtproxyFirstTlsFrameSentLogged = false;
    mtproxyFirstTlsDataReceivedLogged = false;
    ConnectionsManager::getInstance(instanceNum).attachConnection(this);

    memset(&socketAddress, 0, sizeof(sockaddr_in));
    memset(&socketAddress6, 0, sizeof(sockaddr_in6));

    std::string *proxyAddress = &overrideProxyAddress;
    std::string *proxySecret = &overrideProxySecret;
    uint16_t proxyPort = overrideProxyPort;
    int32_t proxyTlsProfile = overrideProxyTlsProfile;
    int32_t proxyClientHelloFragmentation = overrideProxyClientHelloFragmentation;
    if (proxyAddress->empty()) {
        proxyAddress = &ConnectionsManager::getInstance(instanceNum).proxyAddress;
        proxyPort = ConnectionsManager::getInstance(instanceNum).proxyPort;
        proxySecret = &ConnectionsManager::getInstance(instanceNum).proxySecret;
        proxyTlsProfile = ConnectionsManager::getInstance(instanceNum).proxyTlsProfile;
        proxyClientHelloFragmentation = ConnectionsManager::getInstance(instanceNum).proxyClientHelloFragmentation;
    }

    if (!proxyAddress->empty()) {
        currentSecretKind = proxySecret->empty() ? "socks" : mtProxySecretKindName(*proxySecret);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) connecting via proxy %s:%d secret[%d] secret_kind=%s", this, proxyAddress->c_str(), proxyPort, (int) proxySecret->size(), currentSecretKind);
        if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) can't create proxy socket", this);
            closeSocket(1, -1);
            return;
        }
        uint32_t tempBuffLength;
        if (proxySecret->empty()) {
            proxyAuthState = 1;
            tempBuffLength = 1024;
        } else if (proxySecret->size() > 17 && (*proxySecret)[0] == '\xee') {
            proxyAuthState = 10;
            currentSecret = proxySecret->substr(1, 16);
            currentSecretDomain = proxySecret->substr(17);
            currentSecretIsFakeTls = true;
            currentProxyTlsProfile = normalizeMtProxyTlsProfile(proxyTlsProfile);
            currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(proxyClientHelloFragmentation);
            proxyHandshakeAdmissionKey = *proxyAddress + ":" + std::to_string((unsigned int) proxyPort) + ":" + currentSecretDomain;
            tempBuffLength = 65 * 1024;
        } else {
            proxyAuthState = 0;
            tempBuffLength = 0;
        }
        if (tempBuffLength > 0) {
            if (tempBuffer == nullptr || tempBuffer->length < tempBuffLength) {
                if (tempBuffer != nullptr) {
                    delete tempBuffer;
                }
                tempBuffer = new ByteArray(tempBuffLength);
            }
        }
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(proxyPort);
        bool continueCheckAddress;
        if (inet_pton(AF_INET, proxyAddress->c_str(), &socketAddress.sin_addr.s_addr) != 1) {
            continueCheckAddress = true;
            if (LOGS_ENABLED) DEBUG_D("connection(%p) not ipv4 address %s", this, proxyAddress->c_str());
        } else {
            ipv6 = false;
            continueCheckAddress = false;
        }
        if (continueCheckAddress) {
            if (inet_pton(AF_INET6, proxyAddress->c_str(), &socketAddress6.sin6_addr.s6_addr) != 1) {
                continueCheckAddress = true;
                if (LOGS_ENABLED) DEBUG_D("connection(%p) not ipv6 address %s", this, proxyAddress->c_str());
            } else {
                ipv6 = true;
                continueCheckAddress = false;
            }
            if (continueCheckAddress) {
                std::string sslipAddress;
                if (mtProxyExtractSslipIpv4Address(*proxyAddress, &socketAddress.sin_addr, &sslipAddress)) {
                    ipv6 = false;
                    continueCheckAddress = false;
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup resolved_sslip host=%s address=%s", this, proxyAddress->c_str(), sslipAddress.c_str());
                }
            }
            if (continueCheckAddress) {
#ifdef USE_DELEGATE_HOST_RESOLVE
                waitingForHostResolve = *proxyAddress;
                ConnectionsManager::getInstance(instanceNum).delegate->getHostByName(*proxyAddress, instanceNum, this);
                return;
#else
                struct hostent *he;
                if ((he = gethostbyname(proxyAddress->c_str())) == nullptr) {
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address", this, proxyAddress->c_str());
                    closeSocket(1, -1);
                    return;
                }
                struct in_addr **addr_list = (struct in_addr **) he->h_addr_list;
                if (addr_list[0] != nullptr) {
                    socketAddress.sin_addr.s_addr = addr_list[0]->s_addr;
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) resolved host %s address %x", this, proxyAddress->c_str(), addr_list[0]->s_addr);
                    ipv6 = false;
                } else {
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address", this, proxyAddress->c_str());
                    closeSocket(1, -1);
                    return;
                }
#endif
            }
        }
    } else {
        proxyAuthState = 0;
        if ((socketFd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)) < 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) can't create socket", this);
            closeSocket(1, -1);
            return;
        }
        if (ipv6) {
            socketAddress6.sin6_family = AF_INET6;
            socketAddress6.sin6_port = htons(port);
            if (inet_pton(AF_INET6, address.c_str(), &socketAddress6.sin6_addr.s6_addr) != 1) {
                if (LOGS_ENABLED) DEBUG_E("connection(%p) bad ipv6 %s", this, address.c_str());
                closeSocket(1, -1);
                return;
            }
        } else {
            socketAddress.sin_family = AF_INET;
            socketAddress.sin_port = htons(port);
            if (inet_pton(AF_INET, address.c_str(), &socketAddress.sin_addr.s_addr) != 1) {
                if (LOGS_ENABLED) DEBUG_E("connection(%p) bad ipv4 %s", this, address.c_str());
                closeSocket(1, -1);
                return;
            }
        }
        uint32_t tempBuffLength;
        currentSecretKind = mtProxySecretKindName(secret);
        if (secret.size() > 17 && secret[0] == '\xee') {
            proxyAuthState = 10;
            currentSecret = secret.substr(1, 16);
            currentSecretDomain = secret.substr(17);
            currentSecretIsFakeTls = true;
            currentProxyTlsProfile = normalizeMtProxyTlsProfile(ConnectionsManager::getInstance(instanceNum).proxyTlsProfile);
            currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(ConnectionsManager::getInstance(instanceNum).proxyClientHelloFragmentation);
            proxyHandshakeAdmissionKey = address + ":" + std::to_string((unsigned int) port) + ":" + currentSecretDomain;
            tempBuffLength = 65 * 1024;
        } else {
            proxyAuthState = 0;
            tempBuffLength = 0;
        }
        if (tempBuffLength > 0) {
            if (tempBuffer == nullptr || tempBuffer->length < tempBuffLength) {
                if (tempBuffer != nullptr) {
                    delete tempBuffer;
                }
                tempBuffer = new ByteArray(tempBuffLength);
            }
        }
    }

    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup connect_start proxy_state=%d secret_kind=%s is_faketls=%d domain_len=%d profile=%s clienthello_fragment=%d address=%s port=%u", this, (int) proxyAuthState, currentSecretKind, currentSecretIsFakeTls ? 1 : 0, (int) currentSecretDomain.size(), mtProxyTlsProfileName(currentProxyTlsProfile), currentClientHelloFragmentation, currentAddress.c_str(), (unsigned int) currentPort);
    openConnectionInternal(ipv6);
}

void ConnectionSocket::openConnectionInternal(bool ipv6) {
    if (proxyAuthState >= 10) {
        if (scheduleProxyHandshakeAdmissionIfNeeded(ipv6)) {
            return;
        }
    }
    int epolFd = ConnectionsManager::getInstance(instanceNum).epolFd;
    int yes = 1;
    if (setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int))) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) set TCP_NODELAY failed", this);
    }
#ifdef DEBUG_VERSION
    int size = 4 * 1024 * 1024;
    if (setsockopt(socketFd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int))) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) set SO_SNDBUF failed", this);
    }
    if (setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int))) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) set SO_RCVBUF failed", this);
    }
#endif

    if (fcntl(socketFd, F_SETFL, O_NONBLOCK) == -1) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) set O_NONBLOCK failed", this);
        closeSocket(1, -1);
        return;
    }

    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup socket_connect_start ipv6=%d state=%d", this, ipv6 ? 1 : 0, (int) proxyAuthState);
    if (connect(socketFd, (ipv6 ? (sockaddr *) &socketAddress6 : (sockaddr *) &socketAddress), (socklen_t) (ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in))) == -1 && errno != EINPROGRESS) {
        closeSocket(1, -1);
    } else {
        eventMask.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
        eventMask.data.ptr = eventObject;
        if (epoll_ctl(epolFd, EPOLL_CTL_ADD, socketFd, &eventMask) != 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) epoll_ctl, adding socket failed", this);
            closeSocket(1, -1);
        }
    }
    if (adjustWriteOpAfterResolve) {
        adjustWriteOp();
    }
}

int32_t ConnectionSocket::checkSocketError(int32_t *error) {
    if (socketFd < 0) {
        return true;
    }
    int ret;
    int code;
    socklen_t len = sizeof(int);
    ret = getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &code, &len);
    if (ret != 0 || code != 0) {
        if (LOGS_ENABLED) DEBUG_E("socket error 0x%x code 0x%x", ret, code);
    }
    *error = code;
    return (ret || code) != 0;
}

void ConnectionSocket::closeSocket(int32_t reason, int32_t error) {
    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_disconnect reason=%d reason_text=%s error=%d error_text=%s secret_kind=%s is_faketls=%d proxy_state=%d tls_state=%d bytes_read=%zu pending_hello=%u/%u pending=%u/%u first_tls_sent=%d first_tls_recv=%d", this, reason, mtProxyDisconnectReasonName(reason), error, mtProxySocketErrorName(error), currentSecretKind, currentSecretIsFakeTls ? 1 : 0, (int) proxyAuthState, (int) tlsState, bytesRead, pendingClientHelloOffset, pendingClientHelloSize, pendingTlsFrameOffset, pendingTlsFrameSize, mtproxyFirstTlsFrameSentLogged ? 1 : 0, mtproxyFirstTlsDataReceivedLogged ? 1 : 0);
    releaseProxyHandshakeAdmission(false, "closeSocket");
    cancelProxyHandshakeAdmission();
    ConnectionsManager::getInstance(instanceNum).detachConnection(this);
    if (socketFd >= 0) {
        epoll_ctl(ConnectionsManager::getInstance(instanceNum).epolFd, EPOLL_CTL_DEL, socketFd, nullptr);
        if (close(socketFd) != 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) unable to close socket", this);
        }
        socketFd = -1;
    }
    waitingForHostResolve = "";
    adjustWriteOpAfterResolve = false;
    proxyAuthState = 0;
    tlsState = 0;
    onConnectedSent = false;
    mtproxySocketConnectedLogged = false;
    serverHelloHmacMismatchObserved = false;
    serverHelloHmacMismatchTime = 0;
    clearPendingClientHello();
    clearPendingTlsFrame();
    outgoingByteStream->clean();
    if (tlsBuffer != nullptr) {
        tlsBuffer->reuse();
        tlsBuffer = nullptr;
    }
    tlsBufferRecordType = 0;
    onDisconnected(reason, error);
}

void ConnectionSocket::onEvent(uint32_t events) {
    if (events & EPOLLIN) {
        int32_t error;
        if (checkSocketError(&error) != 0) {
            closeSocket(1, error);
            return;
        } else {
            ssize_t readCount;
            NativeByteBuffer *buffer = ConnectionsManager::getInstance(instanceNum).networkBuffer;
            while (true) {
                buffer->rewind();
                readCount = recv(socketFd, buffer->bytes(), READ_BUFFER_SIZE, 0);
                int err = errno;
//                if (LOGS_ENABLED) DEBUG_D("connection(%p) recv resulted with %d, errno=%d", this, readCount, err);
                if (readCount < 0) {
                    if (err == EINTR) {
                        continue;
                    }
                    if (err == EAGAIN || err == EWOULDBLOCK) {
                        break;
                    }
                    closeSocket(1, -1);
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) recv failed", this);
                    return;
                }
                if (readCount > 0) {
                    buffer->limit((uint32_t) readCount);
                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                    if (proxyAuthState == 11) {
                        if (pendingClientHello != nullptr && pendingClientHelloOffset < pendingClientHelloSize && LOGS_ENABLED) {
                            DEBUG_D("connection(%p) mtproxy_startup server_data_before_client_hello_complete pending_hello=%u/%u read=%d", this, pendingClientHelloOffset, pendingClientHelloSize, (int) readCount);
                        }
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS received %d", this, (int) readCount);
                        size_t newBytesRead = bytesRead + readCount;
                        if (newBytesRead > MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES) {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS client hello too much data", this);
                            return;
                        }
                        std::memcpy(tempBuffer->bytes + bytesRead, buffer->bytes(), (size_t) readCount);
                        if (newBytesRead < 5) {
                            bytesRead = newBytesRead;
                            return;
                        }

                        static std::string hello1 = std::string("\x16\x03\x03", 3);
                        if (std::memcmp(hello1.data(), tempBuffer->bytes, hello1.size()) != 0) {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS hello1 mismatch", this);
                            return;
                        }
                        size_t len1 = (tempBuffer->bytes[3] << 8) + tempBuffer->bytes[4];
                        if (len1 > MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES - 16) {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS len1 invalid", this);
                            return;
                        } else if (newBytesRead < len1 + 5) {
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS client hello wait for more data", this);
                            bytesRead = newBytesRead;
                            return;
                        }

                        static std::string hello2 = std::string("\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9);
                        if (std::memcmp(hello2.data(), tempBuffer->bytes + 5 + len1, hello2.size()) != 0) {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS hello2 mismatch", this);
                            return;
                        }
                        size_t len2 = (tempBuffer->bytes[5 + 9 + len1] << 8) + tempBuffer->bytes[5 + 9 + len1 + 1];
                        if (len2 > MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES - len1 - 5 - 11) {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS len2 invalid", this);
                            return;
                        }
                        size_t candidateBytes = len2 + len1 + 5 + 11;
                        if (newBytesRead < candidateBytes) {
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS client hello wait for more data", this);
                            bytesRead = newBytesRead;
                            return;
                        }

                        size_t matchedBytes = 0;
                        size_t appFlightBytes = len2;
                        while (candidateBytes <= newBytesRead) {
                            if (mtProxyVerifyServerHelloHmac(currentSecret, tempBuffer->bytes + MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES, tempBuffer->bytes, candidateBytes)) {
                                matchedBytes = candidateBytes;
                                break;
                            }
                            if (candidateBytes == newBytesRead) {
                                break;
                            }
                            if (newBytesRead - candidateBytes < 5) {
                                if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS server hello wait for tail header bytes=%zu candidate=%zu", this, newBytesRead, candidateBytes);
                                bytesRead = newBytesRead;
                                return;
                            }
                            static std::string appHeader = std::string("\x17\x03\x03", 3);
                            if (std::memcmp(appHeader.data(), tempBuffer->bytes + candidateBytes, appHeader.size()) != 0) {
                                tlsHashMismatch = true;
                                closeSocket(1, -1);
                                if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS server hello tail mismatch at=%zu", this, candidateBytes);
                                return;
                            }
                            size_t nextLen = (tempBuffer->bytes[candidateBytes + 3] << 8) + tempBuffer->bytes[candidateBytes + 4];
                            if (nextLen > MT_PROXY_TLS_SERVER_RESPONSE_MAX_BYTES - candidateBytes - 5) {
                                closeSocket(1, -1);
                                if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS server hello tail len invalid", this);
                                return;
                            }
                            if (newBytesRead < candidateBytes + 5 + nextLen) {
                                if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS server hello wait for tail data bytes=%zu candidate=%zu next=%zu", this, newBytesRead, candidateBytes, nextLen);
                                bytesRead = newBytesRead;
                                return;
                            }
                            candidateBytes += 5 + nextLen;
                            appFlightBytes += 5 + nextLen;
                        }
                        if (matchedBytes == 0) {
                            proxyCheckDiagnostic = "server_hello_hmac_mismatch";
                            serverHelloHmacMismatchObserved = true;
                            if (serverHelloHmacMismatchTime == 0) {
                                serverHelloHmacMismatchTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                                scheduleProxyHandshakeAdmissionTimer((uint32_t) MT_PROXY_SERVER_HELLO_HMAC_WAIT_MS, MT_PROXY_HANDSHAKE_TIMER_SERVER_HELLO, proxyHandshakeAdmissionIpv6);
                            }
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS server hello hmac wait bytes=%zu candidate=%zu", this, newBytesRead, candidateBytes);
                            bytesRead = newBytesRead;
                            return;
                        }
                        serverHelloHmacMismatchObserved = false;
                        serverHelloHmacMismatchTime = 0;
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_ok bytes=%zu len1=%zu len2=%zu flight=%zu extra=%zu", this, matchedBytes, len1, len2, appFlightBytes, newBytesRead - matchedBytes);
                        releaseProxyHandshakeAdmission(true, "server_hello_hmac_ok");
                        proxyCheckDiagnostic = "post_handshake_no_appdata";
                        tlsState = 1;
                        proxyAuthState = 0;
                        bytesRead = 0;
                        adjustWriteOp();
                    } else if (proxyAuthState == 2) {
                        if (readCount == 2) {
                            uint8_t auth_method = buffer->bytes()[1];
                            if (auth_method == 0xff) {
                                closeSocket(1, -1);
                                if (LOGS_ENABLED) DEBUG_E("connection(%p) unsupported proxy auth method", this);
                            } else if (auth_method == 0x02) {
                                if (LOGS_ENABLED) DEBUG_D("connection(%p) proxy auth required", this);
                                proxyAuthState = 3;
                            } else if (auth_method == 0x00) {
                                proxyAuthState = 5;
                            }
                            adjustWriteOp();
                        } else {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) invalid proxy response on state 2", this);
                        }
                    } else if (proxyAuthState == 4) {
                        if (readCount == 2) {
                            uint8_t auth_method = buffer->bytes()[1];
                            if (auth_method != 0x00) {
                                closeSocket(1, -1);
                                if (LOGS_ENABLED) DEBUG_E("connection(%p) auth invalid", this);
                            } else {
                                proxyAuthState = 5;
                            }
                            adjustWriteOp();
                        } else {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) invalid proxy response on state 4", this);
                        }
                    } else if (proxyAuthState == 6) {
                        if (readCount > 2) {
                            uint8_t status = buffer->bytes()[1];
                            if (status == 0x00) {
                                if (LOGS_ENABLED) DEBUG_D("connection(%p) connected via proxy", this);
                                proxyAuthState = 0;
                                adjustWriteOp();
                            } else {
                                closeSocket(1, -1);
                                if (LOGS_ENABLED) DEBUG_E("connection(%p) invalid proxy status on state 6, 0x%x", this, status);
                            }
                        } else {
                            closeSocket(1, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) invalid proxy response on state 6", this);
                        }
                    } else if (proxyAuthState == 0) {
                        if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
                            ConnectionsManager::getInstance(instanceNum).delegate->onBytesReceived((int32_t) readCount, currentNetworkType, instanceNum);
                        }
                        if (tlsState != 0) {
                            while (buffer->hasRemaining()) {
                                size_t newBytesRead = buffer->remaining();
                                if (tlsBuffer != nullptr) {
                                    newBytesRead += tlsBuffer->position();
                                    if (tlsBufferSized) {
                                        newBytesRead += 5;
                                    }
                                }
                                if (newBytesRead >= 5) {
                                    if (tlsBuffer == nullptr || !tlsBufferSized) {
                                        uint32_t pos = buffer->position();

                                        uint8_t offset = 0;
                                        uint8_t header[5];
                                        if (tlsBuffer != nullptr) {
                                            offset = (uint8_t) tlsBuffer->position();
                                            memcpy(header, tlsBuffer->bytes(), offset);
                                            tlsBuffer->reuse();
                                            tlsBuffer = nullptr;
                                        }
                                        memcpy(header + offset, buffer->bytes() + pos, (uint8_t) (5 - offset));

                                        if (header[1] != 0x03 || header[2] != 0x03) {
                                            closeSocket(1, -1);
                                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS response version mismatch type=0x%02x version=0x%02x%02x", this, header[0], header[1], header[2]);
                                            return;
                                        }
                                        uint32_t len1 = (header[3] << 8) + header[4];
                                        if (header[0] == MT_PROXY_TLS_RECORD_APPLICATION_DATA && len1 == 0) {
                                            buffer->position(pos + (5 - offset));
                                            tlsBufferRecordType = 0;
                                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS response empty application data skipped", this);
                                            continue;
                                        }
                                        if (header[0] == MT_PROXY_TLS_RECORD_CHANGE_CIPHER_SPEC && len1 != 1) {
                                            closeSocket(1, -1);
                                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS response CCS len invalid %u", this, len1);
                                            return;
                                        }
                                        if (header[0] == MT_PROXY_TLS_RECORD_ALERT && len1 != 2) {
                                            closeSocket(1, -1);
                                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS response alert len invalid %u", this, len1);
                                            return;
                                        }
                                        if (header[0] != MT_PROXY_TLS_RECORD_APPLICATION_DATA && header[0] != MT_PROXY_TLS_RECORD_CHANGE_CIPHER_SPEC && header[0] != MT_PROXY_TLS_RECORD_ALERT) {
                                            closeSocket(1, -1);
                                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS response record type mismatch 0x%02x", this, header[0]);
                                            return;
                                        }
                                        if (len1 > 64 * 1024) {
                                            closeSocket(1, -1);
                                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS response len1 invalid", this);
                                            return;
                                        } else {
                                            tlsBuffer = BuffersStorage::getInstance().getFreeBuffer(len1);
                                            tlsBufferRecordType = header[0];
                                            tlsBufferSized = true;
                                            buffer->position(pos + (5 - offset));
                                        }
                                    } else {
                                        if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS response new data %d", this, buffer->remaining());
                                    }
                                    buffer->limit(std::min(buffer->position() + tlsBuffer->remaining(), buffer->limit()));
                                    tlsBuffer->writeBytes(buffer);
                                    buffer->limit((uint32_t) readCount);
                                    if (tlsBuffer->remaining() == 0) {
                                        tlsBuffer->rewind();
                                        if (tlsBufferRecordType == MT_PROXY_TLS_RECORD_APPLICATION_DATA) {
                                            if (!mtproxyFirstTlsDataReceivedLogged) {
                                                mtproxyFirstTlsDataReceivedLogged = true;
                                                proxyCheckDiagnostic = "dropped_after_appdata";
                                                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_tls_app_recv payload=%d", this, tlsBuffer->limit());
                                            }
                                            onReceivedData(tlsBuffer);
                                            if (tlsBuffer == nullptr) {
                                                return;
                                            }
                                        } else if (tlsBufferRecordType == MT_PROXY_TLS_RECORD_CHANGE_CIPHER_SPEC) {
                                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS response ChangeCipherSpec skipped", this);
                                        } else if (tlsBufferRecordType == MT_PROXY_TLS_RECORD_ALERT) {
                                            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_disconnect tls_alert", this);
                                            tlsBuffer->reuse();
                                            tlsBuffer = nullptr;
                                            tlsBufferRecordType = 0;
                                            closeSocket(1, 0);
                                            return;
                                        }
                                        tlsBuffer->reuse();
                                        tlsBuffer = nullptr;
                                        tlsBufferRecordType = 0;
                                    } else {
                                        if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS response wait for more data, total size %d, left %d", this, tlsBuffer->limit(), tlsBuffer->remaining());
                                    }
                                } else {
                                    if (tlsBuffer == nullptr) {
                                        tlsBuffer = BuffersStorage::getInstance().getFreeBuffer(4);
                                        tlsBufferSized = false;
                                    }
                                    tlsBuffer->writeBytes(buffer);
                                    if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS response wait for more data, not enough bytes for header, total = %d", this, (int) tlsBuffer->position());
                                }
                            }
                        } else {
                            onReceivedData(buffer);
                        }
                    }
                } else if (readCount == 0) {
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_disconnect recv_eof proxy_state=%d tls_state=%d", this, (int) proxyAuthState, (int) tlsState);
                    closeSocket(1, 0);
                    return;
                }
//                if (readCount != READ_BUFFER_SIZE) {
//                    break;
//                }
            }
        }
    }
    if (events & EPOLLOUT) {
        int32_t error;
        if (checkSocketError(&error) != 0) {
            closeSocket(1, error);
            return;
        } else {
            if (!mtproxySocketConnectedLogged && (proxyAuthState >= 10 || tlsState != 0)) {
                mtproxySocketConnectedLogged = true;
                proxyCheckDiagnostic = "tcp_connected_no_pong";
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup socket_connected state=%d tls=%d", this, (int) proxyAuthState, (int) tlsState);
            }
            if (proxyAuthState != 0) {
                if (proxyAuthState >= 10) {
                    if (proxyAuthState == 10) {
                        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                        tlsHashMismatch = false;
                        serverHelloHmacMismatchObserved = false;
                        serverHelloHmacMismatchTime = 0;
                        proxyAuthState = 11;
                        const char *profileName = mtProxyTlsProfileName(currentProxyTlsProfile);
                        TlsHello hello = selectMtProxyTlsHello(currentProxyTlsProfile);
                        hello.setDomain(currentSecretDomain);
                        uint32_t size = hello.writeToBuffer(tempBuffer->bytes);
                        if (!validateServerCompatibleHello(tempBuffer->bytes, size, currentSecretDomain, profileName)) {
                            closeSocket(1, -1);
                            return;
                        }
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup profile selected=%s id=%d hello=%u", this, profileName, (int) normalizeMtProxyTlsProfile(currentProxyTlsProfile), size);
                        uint32_t outLength;
                        HMAC(EVP_sha256(), currentSecret.data(), currentSecret.size(), tempBuffer->bytes, size, tempBuffer->bytes + 64 * 1024, &outLength);

                        int32_t currentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTime();
                        int32_t old = ((int32_t *) (tempBuffer->bytes + 64 * 1024 + 28))[0];
                        ((int32_t *) (tempBuffer->bytes + 64 * 1024 + 28))[0] = old ^ currentTime;

                        memcpy(tempBuffer->bytes + 11, tempBuffer->bytes + 64 * 1024, 32);
                        bytesRead = 0;

                        if (!buildPendingClientHello(size)) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) ClientHello pending buffer build failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                    }
                    if (proxyAuthState == 11 && pendingClientHello != nullptr) {
                        uint32_t size = pendingClientHelloSize;
                        if (!sendPendingClientHello()) {
                            return;
                        }
                        if (pendingClientHello != nullptr && pendingClientHelloOffset < pendingClientHelloSize) {
                            return;
                        }
                        clearPendingClientHello();
                        proxyCheckDiagnostic = "client_hello_sent_no_server_hello";
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup client_hello_sent bytes=%u expected=%u domain_len=%d", this, size, size, (int) currentSecretDomain.size());
                        markProxyHandshakeClientHelloSent();
                        adjustWriteOp();
                    }
                } else {
                    if (proxyAuthState == 1) {
                        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                        proxyAuthState = 2;
                        tempBuffer->bytes[0] = 0x05;
                        tempBuffer->bytes[1] = 0x02;
                        tempBuffer->bytes[2] = 0x00;
                        tempBuffer->bytes[3] = 0x02;
                        if (send(socketFd, tempBuffer->bytes, 4, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        adjustWriteOp();
                    } else if (proxyAuthState == 3) {
                        tempBuffer->bytes[0] = 0x01;
                        std::string *proxyUser;
                        std::string *proxyPassword;
                        if (!overrideProxyAddress.empty()) {
                            proxyUser = &overrideProxyUser;
                            proxyPassword = &overrideProxyPassword;
                        } else {
                            proxyUser = &ConnectionsManager::getInstance(instanceNum).proxyUser;
                            proxyPassword = &ConnectionsManager::getInstance(instanceNum).proxyPassword;
                        }
                        uint8_t len1 = (uint8_t) proxyUser->length();
                        uint8_t len2 = (uint8_t) proxyPassword->length();
                        tempBuffer->bytes[1] = len1;
                        memcpy(tempBuffer->bytes + 2, proxyUser->c_str(), len1);
                        tempBuffer->bytes[2 + len1] = len2;
                        memcpy(tempBuffer->bytes + 3 + len1, proxyPassword->c_str(), len2);
                        proxyAuthState = 4;
                        if (send(socketFd, tempBuffer->bytes, 3 + len1 + len2, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        adjustWriteOp();
                    } else if (proxyAuthState == 5) {
                        tempBuffer->bytes[0] = 0x05;
                        tempBuffer->bytes[1] = 0x01;
                        tempBuffer->bytes[2] = 0x00;
                        tempBuffer->bytes[3] = (uint8_t) (isIpv6 ? 0x04 : 0x01);
                        uint16_t networkPort = ntohs(currentPort);
                        inet_pton(isIpv6 ? AF_INET6 : AF_INET, currentAddress.c_str(), tempBuffer->bytes + 4);
                        memcpy(tempBuffer->bytes + 4 + (isIpv6 ? 16 : 4), &networkPort, sizeof(uint16_t));
                        proxyAuthState = 6;
                        if (send(socketFd, tempBuffer->bytes, 4 + (isIpv6 ? 16 : 4) + 2, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        adjustWriteOp();
                    }
                }
            } else {
                if (!onConnectedSent) {
                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup on_connected tls=%d", this, (int) tlsState);
                    onConnected();
                    onConnectedSent = true;
                }
                if (tlsState != 0 && pendingTlsFrame != nullptr) {
                    if (!sendPendingTlsFrame()) {
                        return;
                    }
                    if (pendingTlsFrame != nullptr) {
                        return;
                    }
                }

                NativeByteBuffer *buffer = ConnectionsManager::getInstance(instanceNum).networkBuffer;
                buffer->clear();
                outgoingByteStream->get(buffer);
                buffer->flip();
                uint32_t remaining = buffer->remaining();
                if (remaining) {
                    ssize_t sentLength;
                    if (tlsState != 0) {
                        if (!buildPendingTlsFrame(buffer, remaining)) {
                            return;
                        }
                        if (!sendPendingTlsFrame()) {
                            return;
                        }
                    } else {
                        if ((sentLength = send(socketFd, buffer->bytes(), remaining, 0)) < 0) {
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        } else {
                            if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
                                ConnectionsManager::getInstance(instanceNum).delegate->onBytesSent((int32_t) sentLength, currentNetworkType, instanceNum);
                            }
                            outgoingByteStream->discard((uint32_t) sentLength);
                            adjustWriteOp();
                        }
                    }
                }
            }
        }
    }
    if (events & EPOLLHUP) {
        if (LOGS_ENABLED) DEBUG_E("socket event has EPOLLHUP");
        closeSocket(1, -1);
        return;
    } else if (events & EPOLLRDHUP) {
        if (LOGS_ENABLED) DEBUG_E("socket event has EPOLLRDHUP");
        closeSocket(1, -1);
        return;
    }
    if (events & EPOLLERR) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) epoll error", this);
        return;
    }
}

void ConnectionSocket::writeBuffer(uint8_t *data, uint32_t size) {
    NativeByteBuffer *buffer = BuffersStorage::getInstance().getFreeBuffer(size);
    buffer->writeBytes(data, size);
    outgoingByteStream->append(buffer);
    adjustWriteOp();
}

void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer) {
    outgoingByteStream->append(buffer);
    adjustWriteOp();
}

void ConnectionSocket::adjustWriteOp() {
    if (!waitingForHostResolve.empty()) {
        adjustWriteOpAfterResolve = true;
        return;
    }
    eventMask.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
    bool hasPendingClientHello = pendingClientHello != nullptr && pendingClientHelloOffset < pendingClientHelloSize;
    bool hasPendingTlsFrame = pendingTlsFrame != nullptr && pendingTlsFrameOffset < pendingTlsFrameSize;
    if ((proxyAuthState == 0 && (hasPendingTlsFrame || outgoingByteStream->hasData() || !onConnectedSent)) || proxyAuthState == 1 || proxyAuthState == 3 || proxyAuthState == 5 || proxyAuthState == 10 || (proxyAuthState == 11 && hasPendingClientHello)) {
        eventMask.events |= EPOLLOUT;
    }
    eventMask.data.ptr = eventObject;
    if (epoll_ctl(ConnectionsManager::getInstance(instanceNum).epolFd, EPOLL_CTL_MOD, socketFd, &eventMask) != 0) {
        if (LOGS_ENABLED) DEBUG_E("connection(%p) epoll_ctl, modify socket failed", this);
        closeSocket(1, -1);
    }
}

void ConnectionSocket::setTimeout(time_t time) {
    timeout = time;
    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    if (LOGS_ENABLED) DEBUG_D("connection(%p) set current timeout = %lld", this, (long long) timeout);
}

time_t ConnectionSocket::getTimeout() {
    return timeout;
}

bool ConnectionSocket::checkTimeout(int64_t now) {
    if (timeout != 0 && (now - lastEventTime) > (int64_t) timeout * 1000) {
        if (!onConnectedSent || hasPendingRequests()) {
            closeSocket(2, 0);
            return true;
        } else {
            lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
            if (LOGS_ENABLED) DEBUG_D("connection(%p) reset last event time, no requests", this);
        }
    }
    return false;
}

bool ConnectionSocket::hasTlsHashMismatch() {
    return tlsHashMismatch;
}

void ConnectionSocket::resetLastEventTime() {
    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
}

bool ConnectionSocket::isDisconnected() {
    return socketFd < 0;
}

void ConnectionSocket::dropConnection() {
    closeSocket(0, 0);
}

void ConnectionSocket::setMtProxyHandshakePriority(int32_t priority) {
    if (priority < MT_PROXY_HANDSHAKE_PRIORITY_BYPASS || priority > MT_PROXY_HANDSHAKE_PRIORITY_PROXY_CHECK) {
        priority = MT_PROXY_HANDSHAKE_PRIORITY_PROXY_CHECK;
    }
    proxyHandshakeAdmissionPriority = priority;
}

void ConnectionSocket::setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, int32_t mtProxyTlsProfile, int32_t mtProxyClientHelloFragmentation) {
    overrideProxyAddress = address;
    overrideProxyPort = port;
    overrideProxyUser = username;
    overrideProxyPassword = password;
    overrideProxySecret = secret;
    overrideProxyTlsProfile = normalizeMtProxyTlsProfile(mtProxyTlsProfile);
    overrideProxyClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(mtProxyClientHelloFragmentation);
}

void ConnectionSocket::onHostNameResolved(std::string host, std::string ip, bool ipv6) {
    ConnectionsManager::getInstance(instanceNum).scheduleTask([&, host, ip, ipv6] {
        if (waitingForHostResolve == host) {
            waitingForHostResolve = "";
            if (ip.empty() || inet_pton(AF_INET, ip.c_str(), &socketAddress.sin_addr.s_addr) != 1) {
                if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address via delegate", this, host.c_str());
                closeSocket(1, -1);
                return;
            }
            if (LOGS_ENABLED) DEBUG_D("connection(%p) resolved host %s address %s via delegate", this, host.c_str(), ip.c_str());
            openConnectionInternal(ipv6);
        }
    });
}
