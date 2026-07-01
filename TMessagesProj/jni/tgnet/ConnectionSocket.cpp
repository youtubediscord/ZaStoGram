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
#include <openssl/sha.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
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
#include "MtProxyAdaptivePolicy.h"
#include "MtProxyDataPathShaper.h"
#include "MtProxyEndpointPolicy.h"
#include "MtProxyFailureEvidence.h"
#include "MtProxyHandshakePlan.h"
#include "MtProxyHandshakeScheduler.h"
#include "MtProxyPhaseContract.h"
#include "MtProxyProbeCoordinator.h"
#include "MtProxyRecoveryPolicy.h"
#include "MtProxySecretDomain.h"
#include "MtProxyServerFlightParser.h"
#include "MtProxySocketPublisher.h"
#include <random>
#include <pthread.h>

#define outgoingByteStream stateMachine.socket.outgoingByteStream
#define eventMask stateMachine.socket.eventMask
#define socketAddress stateMachine.socket.address
#define socketAddress6 stateMachine.socket.address6
#define socketFd stateMachine.socket.fd
#define epollRegistered stateMachine.epoll.registered
#define currentTransportState stateMachine.diagnostics.lifecycle
#define timeout stateMachine.socket.timeout
#define onConnectedSent stateMachine.notification.connectedSent
#define socketCloseNotified stateMachine.notification.closeNotified
#define proxyCloseDiagnosticSuppressed stateMachine.notification.closeDiagnosticSuppressed
#define socketDeadForWrites stateMachine.notification.deadForWrites
#define lastEventTime stateMachine.socket.lastEventTime
#define eventObject stateMachine.socket.eventObject
#define currentNetworkType stateMachine.socket.currentNetworkType
#define isIpv6 stateMachine.socket.isIpv6
#define currentAddress stateMachine.socket.currentAddress
#define currentPort stateMachine.socket.currentPort
#define currentSocksUsername stateMachine.socket.currentSocksUsername
#define currentSocksPassword stateMachine.socket.currentSocksPassword
#define waitingForHostResolve stateMachine.hostResolve.waitingHost
#define adjustWriteOpAfterResolve stateMachine.hostResolve.adjustWriteAfterResolve
#define currentSecret stateMachine.diagnostics.currentSecret
#define currentSecretDomain stateMachine.diagnostics.currentSecretDomain
#define currentOriginalSecretDomain stateMachine.diagnostics.currentOriginalSecretDomain
#define currentSanitizedSecretDomain stateMachine.diagnostics.currentSanitizedSecretDomain
#define currentLowercaseSecretDomain stateMachine.diagnostics.currentLowercaseSecretDomain
#define currentNoTrailingDotSecretDomain stateMachine.diagnostics.currentNoTrailingDotSecretDomain
#define currentPunycodeSecretDomain stateMachine.diagnostics.currentPunycodeSecretDomain
#define currentClientHelloSni stateMachine.diagnostics.currentClientHelloSni
#define currentSecretKind stateMachine.diagnostics.currentSecretKind
#define currentSecretIsFakeTls stateMachine.diagnostics.currentSecretIsFakeTls
#define currentAllowedSniVariants stateMachine.diagnostics.currentAllowedSniVariants
#define currentRecipeFamily stateMachine.diagnostics.currentRecipeFamily
#define currentRecipeSniVariant stateMachine.diagnostics.currentRecipeSniVariant
#define currentRecipeParserVariant stateMachine.diagnostics.currentRecipeParserVariant
#define currentRecipeClassicVariant stateMachine.diagnostics.currentRecipeClassicVariant
#define currentProxyTlsProfile stateMachine.diagnostics.currentProxyTlsProfile
#define currentEffectiveProxyTlsProfile stateMachine.diagnostics.currentEffectiveProxyTlsProfile
#define currentClientHelloFragmentation stateMachine.diagnostics.currentClientHelloFragmentation
#define currentServerHelloParserMode stateMachine.diagnostics.currentServerHelloParserMode
#define currentConnectionPatternMode stateMachine.diagnostics.currentConnectionPatternMode
#define currentRecordSizingMode stateMachine.diagnostics.currentRecordSizingMode
#define currentTimingMode stateMachine.diagnostics.currentTimingMode
#define currentStartupCoverMode stateMachine.diagnostics.currentStartupCoverMode
#define startupCoverStartTime stateMachine.fakeTls.startupCoverStartTime
#define startupCoverFrameCount stateMachine.fakeTls.startupCoverFrameCount
#define startupCoverStartedLogged stateMachine.fakeTls.startupCoverStartedLogged
#define startupCoverEndedLogged stateMachine.fakeTls.startupCoverEndedLogged
#define adjustWriteOpAfterPreTcpGate stateMachine.pendingWrite.adjustWriteAfterPreTcpGate
#define currentProxyTlsProfileKey stateMachine.diagnostics.currentProxyTlsProfileKey
#define currentMtProxyEndpointKey stateMachine.diagnostics.currentMtProxyEndpointKey
#define currentMtProxyRecipeCacheKey stateMachine.diagnostics.currentMtProxyRecipeCacheKey
#define currentMtProxyProbeKey stateMachine.diagnostics.currentMtProxyProbeKey
#define currentMtProxyNetworkEndpointKey stateMachine.diagnostics.currentMtProxyNetworkEndpointKey
#define currentMtProxyDnsCacheKey stateMachine.diagnostics.currentMtProxyDnsCacheKey
#define currentMtProxyAdmissionKey stateMachine.diagnostics.currentMtProxyAdmissionKey
#define proxyCheckDiagnostic stateMachine.diagnostics.proxyCheckDiagnostic
#define startupTimeline stateMachine.diagnostics.startupTimeline
#define tlsHashMismatch stateMachine.fakeTls.tlsHashMismatch
#define serverHelloHmacMismatchObserved stateMachine.fakeTls.serverHelloHmacMismatchObserved
#define serverHelloHmacMismatchTime stateMachine.fakeTls.serverHelloHmacMismatchTime
#define tlsBufferSized stateMachine.fakeTls.tlsBufferSized
#define tlsBufferRecordType stateMachine.fakeTls.tlsBufferRecordType
#define tlsBuffer stateMachine.fakeTls.tlsBuffer
#define tempBuffer stateMachine.pendingWrite.tempBuffer
#define pendingClientHello stateMachine.fakeTls.pendingClientHello
#define pendingTlsFrame stateMachine.fakeTls.pendingTlsFrame
#define bytesRead stateMachine.pendingWrite.bytesRead
#define pendingClientHelloSize stateMachine.fakeTls.pendingClientHelloSize
#define pendingClientHelloOffset stateMachine.fakeTls.pendingClientHelloOffset
#define pendingClientHelloFragmentTarget stateMachine.fakeTls.pendingClientHelloFragmentTarget
#define pendingClientHelloFragmentIndex stateMachine.fakeTls.pendingClientHelloFragmentIndex
#define pendingClientHelloFragmentCount stateMachine.fakeTls.pendingClientHelloFragmentCount
#define pendingClientHelloNextWriteTime stateMachine.fakeTls.pendingClientHelloNextWriteTime
#define pendingTlsFrameSize stateMachine.fakeTls.pendingTlsFrameSize
#define pendingTlsFrameOffset stateMachine.fakeTls.pendingTlsFrameOffset
#define pendingTlsPayloadSize stateMachine.fakeTls.pendingTlsPayloadSize
#define nextTlsFrameWriteTime stateMachine.fakeTls.nextTlsFrameWriteTime
#define tlsState stateMachine.fakeTls.tlsState
#define mtproxyFirstTlsFrameSentLogged stateMachine.fakeTls.mtproxyFirstTlsFrameSentLogged
#define mtproxyFirstTlsDataReceivedLogged stateMachine.fakeTls.mtproxyFirstTlsDataReceivedLogged
#define mtproxyFirstPlainDataSentLogged stateMachine.fakeTls.mtproxyFirstPlainDataSentLogged
#define mtproxyFirstPlainDataReceivedLogged stateMachine.fakeTls.mtproxyFirstPlainDataReceivedLogged
#define firstTransportPacketSent stateMachine.fakeTls.firstTransportPacketSent
#define firstTransportPacketReceived stateMachine.fakeTls.firstTransportPacketReceived
#define dataPathProven stateMachine.fakeTls.dataPathProven
#define mtproxyFirstTlsFrameSentTime stateMachine.fakeTls.mtproxyFirstTlsFrameSentTime
#define mtproxyFirstPlainDataSentTime stateMachine.fakeTls.mtproxyFirstPlainDataSentTime
#define mtproxyFirstDataReceivedTime stateMachine.fakeTls.mtproxyFirstDataReceivedTime
#define mtproxyTlsFrameCompletedCount stateMachine.fakeTls.mtproxyTlsFrameCompletedCount
#define currentTransportWss stateMachine.wss.active
#define currentDatacenterId stateMachine.wss.datacenterId
#define currentMediaConnection stateMachine.wss.mediaConnection
#define currentWssRoute stateMachine.wss.route
#define currentWssTransport stateMachine.wss.transport
#define proxyAuthState stateMachine.socks.proxyAuthState
#define proxyHandshakeAdmissionTimer stateMachine.admission.timer
#define proxyHandshakeAdmissionQueued stateMachine.admission.queued
#define proxyHandshakeAdmissionQueuePublished stateMachine.admission.queuePublished
#define proxyHandshakeAdmissionActive stateMachine.admission.active
#define proxyHandshakeAdmissionReady stateMachine.admission.ready
#define proxyEndpointBackoffReady stateMachine.endpointGate.backoffReady
#define proxyEndpointTcpConnectActive stateMachine.endpointGate.tcpConnectActive
#define proxyEndpointTcpConnectReady stateMachine.endpointGate.tcpConnectReady
#define proxyEndpointTcpConnectGatePublished stateMachine.endpointGate.tcpConnectGatePublished
#define proxyEndpointDnsCoalesceReady stateMachine.endpointGate.dnsCoalesceReady
#define proxyHandshakeAdmissionIpv6 stateMachine.admission.ipv6
#define mtproxySocketConnectedLogged stateMachine.notification.mtproxySocketConnectedLogged
#define proxyHandshakeAdmissionGeneration stateMachine.admission.generation
#define proxyHandshakeAdmissionTimerGeneration stateMachine.admission.timerGeneration
#define proxyHandshakeAdmissionPriority stateMachine.admission.priority
#define proxyHandshakeAdmissionTimerMode stateMachine.admission.timerMode
#define proxyHandshakeAdmissionStartTime stateMachine.admission.startTime
#define proxyHandshakeClientHelloSentTime stateMachine.admission.clientHelloSentTime
#define proxyHandshakeAdmissionKey stateMachine.admission.key

static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_ADMISSION = 1;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_FREEZE = 2;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_SERVER_HELLO = 3;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_CLIENT_HELLO_FRAGMENT = 4;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_TLS_FRAME = 5;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_HOST_RESOLVE = 6;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF = 7;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE = 8;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE = 9;
static constexpr int32_t MT_PROXY_HANDSHAKE_TIMER_PROBE_WAIT = 10;
static constexpr int64_t MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS = 4500;
static constexpr int64_t MT_PROXY_SERVER_HELLO_HMAC_WAIT_MS = 900;
static constexpr int64_t MT_PROXY_PLAIN_NO_RESPONSE_TIMEOUT_MS = 5500;
static constexpr int64_t MT_PROXY_TLS_APPDATA_NO_RESPONSE_TIMEOUT_MS = 5500;
static constexpr int64_t MT_PROXY_EARLY_APPDATA_DROP_MS = 2 * 60 * 1000;
static constexpr bool MT_PROXY_HANDSHAKE_CLOSE_ON_FREEZE_ENABLED = true;
static constexpr uint8_t MT_PROXY_TLS_RECORD_CHANGE_CIPHER_SPEC = 0x14;
static constexpr uint8_t MT_PROXY_TLS_RECORD_ALERT = 0x15;
static constexpr uint8_t MT_PROXY_TLS_RECORD_APPLICATION_DATA = 0x17;

static std::string mtProxyHexPreview(const uint8_t *data, size_t size) {
    static const char hex[] = "0123456789abcdef";
    const size_t limit = std::min<size_t>(size, 32);
    std::string result;
    result.reserve(limit * 2);
    for (size_t i = 0; i < limit; i++) {
        uint8_t value = data[i];
        result.push_back(hex[value >> 4]);
        result.push_back(hex[value & 0x0f]);
    }
    return result;
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

// Crypto-secure RNG for FakeTLS profile variance and runtime-gated data shaping.
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

static int32_t normalizeMtProxyConnectionPatternMode(int32_t mode) {
    if (mode >= MT_PROXY_CONNECTION_PATTERN_OFF && mode <= MT_PROXY_CONNECTION_PATTERN_BROWSER) {
        return mode;
    }
    return MT_PROXY_CONNECTION_PATTERN_OFF;
}

static const char *mtProxyConnectionPatternModeName(int32_t mode) {
    switch (normalizeMtProxyConnectionPatternMode(mode)) {
        case MT_PROXY_CONNECTION_PATTERN_SOFT:
            return "soft";
        case MT_PROXY_CONNECTION_PATTERN_BROWSER:
            return "browser";
        case MT_PROXY_CONNECTION_PATTERN_QUIET:
            return "quiet";
        case MT_PROXY_CONNECTION_PATTERN_STRICT:
            return "strict";
        case MT_PROXY_CONNECTION_PATTERN_OFF:
        default:
            return "off";
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

    static TlsHello getChromeModernDefault() {
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
                        { Op::string("\x00\x0b\x00\x02\x00\x00", 6) },
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
                        { Op::string("\x44\x69\x00\x05\x00\x03\x02\x68\x32", 9) },
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

    static TlsHello getLegacyNoGreaseDefault() {
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
                Op::string("\x00\x1a", 2),
                Op::string("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\x00\x9c\x00\x9d\x00\x2f\x00\x35", 26),
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
                Op::string("\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18", 12),
                Op::string("\x00\x0b\x00\x02\x01\x00", 6),
                Op::string("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 18),
                Op::string("\x00\x0d\x00\x14\x00\x12\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x02\x03", 24),
                Op::string("\x00\x2b\x00\x05\x04\x03\x04\x03\x03", 9),
                Op::string("\x00\x2d\x00\x02\x01\x01", 6),
                Op::string("\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20", 10),
                Op::K(),
                Op::end_scope(),
                Op::end_scope(),
                Op::end_scope()
        };
        return res;
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
    if (profile == MT_PROXY_TLS_PROFILE_AUTO || profile == MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        return profile;
    }
    if (profile >= MT_PROXY_TLS_PROFILE_FIREFOX && profile <= MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE) {
        return profile;
    }
    return MT_PROXY_TLS_PROFILE_ANDROID_CHROME;
}

static int32_t normalizeMtProxyClientHelloFragmentation(int32_t mode) {
    return mode == MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT ? MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT : MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
}

static int32_t normalizeMtProxyRecordSizingMode(int32_t mode) {
    if (mode >= MT_PROXY_RECORD_SIZING_OFF && mode <= MT_PROXY_RECORD_SIZING_VARIED) {
        return mode;
    }
    return MT_PROXY_RECORD_SIZING_OFF;
}

static int32_t normalizeMtProxyTimingMode(int32_t mode) {
    if (mode >= MT_PROXY_TIMING_OFF && mode <= MT_PROXY_TIMING_BALANCED) {
        return mode;
    }
    return MT_PROXY_TIMING_OFF;
}

static int32_t normalizeMtProxyStartupCoverMode(int32_t mode) {
    if (mode >= MT_PROXY_STARTUP_COVER_OFF && mode <= MT_PROXY_STARTUP_COVER_STRICT) {
        return mode;
    }
    return MT_PROXY_STARTUP_COVER_OFF;
}

static const char *mtProxyTlsProfileName(int32_t profile) {
    switch (normalizeMtProxyTlsProfile(profile)) {
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

static std::string mtProxySecretHashForRecipeKey(const std::string &secret) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *) secret.data(), secret.size(), digest);
    char hex[17];
    for (int i = 0; i < 8; i++) {
        std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[16] = '\0';
    return hex;
}

static std::string mtProxyRecipeCacheKeyFor(const std::string &host, uint16_t port, const std::string &secret, const std::string &sni) {
    std::string key = MtProxyEndpointPolicy::networkEndpointKeyFor(host, port);
    key += ":secret_hash=";
    key += mtProxySecretHashForRecipeKey(secret);
    if (!sni.empty()) {
        key += ":";
        key += sni;
    }
    return key;
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
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return TlsHello::getChromeModernDefault();
        case MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE:
            return TlsHello::getLegacyNoGreaseDefault();
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

static uint16_t readBigEndian16(const uint8_t *data) {
    return (uint16_t) (((uint16_t) data[0] << 8) | data[1]);
}

static void appendHex16(std::string &target, uint16_t value) {
    char buffer[8];
    std::snprintf(buffer, sizeof(buffer), "%04x", value);
    if (!target.empty()) {
        target += ",";
    }
    target += buffer;
}

static void appendGreaseValue(std::string &target, uint16_t value) {
    if (isGreaseValue(value)) {
        appendHex16(target, value);
    }
}

static void logClientHelloFingerprint(const void *socket, const char *profileName, const uint8_t *data, uint32_t size) {
    if (!LOGS_ENABLED) {
        return;
    }
    std::string greaseValues;
    std::string greaseExtensions;
    bool has4469 = false;
    bool has44cd = false;
    auto logParsed = [&]() {
        if (greaseValues.empty()) {
            greaseValues = "-";
        }
        if (greaseExtensions.empty()) {
            greaseExtensions = "-";
        }
        DEBUG_D("connection(%p) mtproxy_startup client_hello_fingerprint profile=%s size=%u grease_values=%s grease_exts=%s has_4469=%d has_44cd=%d", socket, profileName != nullptr ? profileName : "unknown", size, greaseValues.c_str(), greaseExtensions.c_str(), has4469 ? 1 : 0, has44cd ? 1 : 0);
    };
    auto logInvalid = [&](const char *reason) {
        DEBUG_D("connection(%p) mtproxy_startup client_hello_fingerprint profile=%s size=%u parse=0 reason=%s grease_values=- grease_exts=- has_4469=0 has_44cd=0", socket, profileName != nullptr ? profileName : "unknown", size, reason != nullptr ? reason : "unknown");
    };

    if (data == nullptr || size < 100 || data[0] != 0x16 || data[5] != 0x01) {
        logInvalid("prefix");
        return;
    }
    uint32_t pos = 11 + 32;
    if (pos >= size) {
        logInvalid("random");
        return;
    }
    uint32_t sessionLength = data[pos++];
    if (pos + sessionLength + 2 > size) {
        logInvalid("session");
        return;
    }
    pos += sessionLength;

    uint32_t cipherSuitesLength = readBigEndian16(data + pos);
    pos += 2;
    if (cipherSuitesLength < 2 || (cipherSuitesLength % 2) != 0 || pos + cipherSuitesLength > size) {
        logInvalid("ciphers");
        return;
    }
    uint32_t cipherSuitesEnd = pos + cipherSuitesLength;
    while (pos + 1 < cipherSuitesEnd) {
        appendGreaseValue(greaseValues, readBigEndian16(data + pos));
        pos += 2;
    }

    if (pos >= size) {
        logInvalid("compression");
        return;
    }
    uint32_t compressionLength = data[pos++];
    if (pos + compressionLength + 2 > size) {
        logInvalid("compression_len");
        return;
    }
    pos += compressionLength;

    uint32_t extensionsLength = readBigEndian16(data + pos);
    pos += 2;
    if (pos + extensionsLength > size) {
        logInvalid("extensions");
        return;
    }
    uint32_t extensionsEnd = pos + extensionsLength;
    while (pos + 4 <= extensionsEnd) {
        uint16_t extensionType = readBigEndian16(data + pos);
        uint32_t extensionLength = readBigEndian16(data + pos + 2);
        pos += 4;
        if (pos + extensionLength > extensionsEnd) {
            logInvalid("extension_len");
            return;
        }
        uint32_t extensionData = pos;
        uint32_t extensionEnd = pos + extensionLength;
        if (extensionType == 0x4469) {
            has4469 = true;
        } else if (extensionType == 0x44cd) {
            has44cd = true;
        }
        if (isGreaseValue(extensionType)) {
            appendHex16(greaseExtensions, extensionType);
            appendGreaseValue(greaseValues, extensionType);
        } else if (extensionType == 0x000a && extensionLength >= 2) {
            uint32_t listLength = readBigEndian16(data + extensionData);
            uint32_t listPos = extensionData + 2;
            uint32_t listEnd = listPos + listLength;
            if (listEnd <= extensionEnd) {
                while (listPos + 1 < listEnd) {
                    appendGreaseValue(greaseValues, readBigEndian16(data + listPos));
                    listPos += 2;
                }
            }
        } else if (extensionType == 0x002b && extensionLength >= 1) {
            uint32_t listLength = data[extensionData];
            uint32_t listPos = extensionData + 1;
            uint32_t listEnd = listPos + listLength;
            if (listEnd <= extensionEnd) {
                while (listPos + 1 < listEnd) {
                    appendGreaseValue(greaseValues, readBigEndian16(data + listPos));
                    listPos += 2;
                }
            }
        } else if (extensionType == 0x0033 && extensionLength >= 2) {
            uint32_t listLength = readBigEndian16(data + extensionData);
            uint32_t listPos = extensionData + 2;
            uint32_t listEnd = listPos + listLength;
            if (listEnd <= extensionEnd) {
                while (listPos + 3 < listEnd) {
                    uint16_t group = readBigEndian16(data + listPos);
                    uint32_t keyLength = readBigEndian16(data + listPos + 2);
                    appendGreaseValue(greaseValues, group);
                    listPos += 4;
                    if (listPos + keyLength > listEnd) {
                        break;
                    }
                    listPos += keyLength;
                }
            }
        }
        pos = extensionEnd;
    }
    logParsed();
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
    if (domainSize == 0) {
        return true;
    }
    if (std::search(data, data + size, (const uint8_t *) domain.data(), (const uint8_t *) domain.data() + domainSize) == data + size) {
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
    releaseMtProxyProbeLease();
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

bool ConnectionSocket::scheduleProxyHandshakeAdmissionIfNeeded(bool ipv6, int32_t timerMode) {
    if (proxyAuthState < 10 || socketFd < 0) {
        return false;
    }
    int32_t connectionPatternMode = normalizeMtProxyConnectionPatternMode(currentConnectionPatternMode);
    if (!mtProxyHandshakeSchedulerUsesAdmission(connectionPatternMode)) {
        if (proxyHandshakeAdmissionKey.empty()) {
            proxyHandshakeAdmissionKey = currentMtProxyAdmissionKey;
        }
        if (proxyHandshakeAdmissionKey.empty()) {
            return false;
        }
        setProxyHandshakeAdmissionState(0, 0, 1, 0, "admission_disabled");
        proxyHandshakeAdmissionIpv6 = ipv6;
        proxyHandshakeAdmissionStartTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
        proxyHandshakeClientHelloSentTime = 0;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_disabled admission_mode=%s connection_pattern=%s key=%s priority=%d", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority);
        return false;
    }
    if (proxyHandshakeAdmissionPriority == MT_PROXY_HANDSHAKE_PRIORITY_BYPASS) {
        return false;
    }
    if (proxyHandshakeAdmissionReady) {
        setProxyHandshakeAdmissionState(-1, -1, -1, 0, "admission_ready_consumed");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "admission_ready_consumed");
        return false;
    }
    if (proxyHandshakeAdmissionKey.empty()) {
        proxyHandshakeAdmissionKey = currentMtProxyAdmissionKey;
    }
    if (proxyHandshakeAdmissionKey.empty()) {
        return false;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyHandshakeAdmissionRequest request;
    request.socket = this;
    request.key = proxyHandshakeAdmissionKey;
    request.generation = proxyHandshakeAdmissionGeneration;
    request.requestClass = mtProxyRequestClassForPriority(proxyHandshakeAdmissionPriority);
    request.priority = proxyHandshakeAdmissionPriority;
    request.timerMode = timerMode;
    request.connectionPatternMode = connectionPatternMode;
    request.ipv6 = ipv6;
    request.queueAlreadyPublished = proxyHandshakeAdmissionQueuePublished;
    request.now = now;
    MtProxyHandshakeAdmissionDecision decision = mtProxyHandshakeSchedulerAdmit(request);

    if (decision.queued) {
        if (decision.publishQueue) {
            setProxyHandshakeAdmissionState(-1, 1, -1, -1, "admission_queue_publish");
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_queue admission_mode=%s connection_pattern=%s key=%s request_class=%s priority=%d active=%d limit=%d global_active=%d global_limit=%d queued=%d cooldown_ms=%ld retry=%u", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionKey.c_str(), mtProxyRequestClassName(request.requestClass), proxyHandshakeAdmissionPriority, decision.endpointActive, decision.endpointLimit, decision.globalActive, decision.globalLimit, decision.queuedCount, (long) decision.cooldownRemainingMs, decision.delayMs);
            publishProxyConnectionStage("admission_queue");
        } else if (LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_startup admission_queue_wait admission_mode=%s connection_pattern=%s key=%s request_class=%s priority=%d active=%d limit=%d global_active=%d global_limit=%d queued=%d cooldown_ms=%ld retry=%u", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionKey.c_str(), mtProxyRequestClassName(request.requestClass), proxyHandshakeAdmissionPriority, decision.endpointActive, decision.endpointLimit, decision.globalActive, decision.globalLimit, decision.queuedCount, (long) decision.cooldownRemainingMs, decision.delayMs);
        }
    } else if (decision.granted) {
        setProxyHandshakeAdmissionState(0, 0, 1, -1, "admission_grant");
        proxyHandshakeAdmissionStartTime = now;
        proxyHandshakeClientHelloSentTime = 0;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_grant admission_mode=%s connection_pattern=%s key=%s request_class=%s priority=%d active=%d limit=%d global_active=%d global_limit=%d delay=%u successes=%d", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionKey.c_str(), mtProxyRequestClassName(request.requestClass), proxyHandshakeAdmissionPriority, decision.endpointActive, decision.endpointLimit, decision.globalActive, decision.globalLimit, decision.delayMs, decision.recentSuccesses);
    }

    if (decision.queued) {
        setProxyHandshakeAdmissionState(1, -1, -1, -1, "admission_queue");
        setTransportState(TransportState::WaitingGate, "admission_queue");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::AdmissionQueue, now + decision.delayMs, "admission_queue");
        scheduleProxyHandshakeAdmissionTimer(decision.delayMs, timerMode, ipv6);
        return true;
    }
    if (decision.delayMs == 0) {
        if (timerMode != MT_PROXY_HANDSHAKE_TIMER_ADMISSION) {
            setProxyHandshakeAdmissionState(-1, -1, -1, 1, "admission_zero_delay_ready");
        }
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "admission_zero_delay_ready");
        return false;
    }

    setProxyHandshakeAdmissionState(-1, -1, -1, 1, "admission_delay");
    setTransportState(TransportState::WaitingGate, "admission_delay");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::AdmissionQueue, now + decision.delayMs, "admission_delay");
    scheduleProxyHandshakeAdmissionTimer(decision.delayMs, timerMode, ipv6);
    return true;
}

void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer(uint32_t delay, int32_t mode, bool ipv6) {
    if (proxyHandshakeAdmissionTimer == nullptr) {
        proxyHandshakeAdmissionTimer = new Timer(instanceNum, [this] {
            if (proxyHandshakeAdmissionTimer != nullptr) {
                proxyHandshakeAdmissionTimer->stop();
            }
            uint32_t timerGeneration = proxyHandshakeAdmissionTimerGeneration;
            int32_t mode = proxyHandshakeAdmissionTimerMode;
            if (timerGeneration != proxyHandshakeAdmissionGeneration || mode == 0) {
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_timer_ignored generation=%u current_generation=%u mode=%d", this, timerGeneration, proxyHandshakeAdmissionGeneration, mode);
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_PROBE_WAIT) {
                proxyHandshakeAdmissionTimerMode = 0;
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                mtProxyProbeWaitTimerFire(delayedIpv6);
                return;
            }
            bool preTcpTimer = mode == MT_PROXY_HANDSHAKE_TIMER_ADMISSION
                    || mode == MT_PROXY_HANDSHAKE_TIMER_HOST_RESOLVE
                    || mode == MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF
                    || mode == MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE
                    || mode == MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE;
            if (preTcpTimer && !canRunMtProxyPreTcpTimer(mtProxyStartupTimerKindForMode(mode), timerGeneration)) {
                proxyHandshakeAdmissionTimerMode = 0;
                return;
            }
            proxyHandshakeAdmissionTimerMode = 0;
            if (socketFd < 0) {
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_HOST_RESOLVE) {
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_host_resolve_timer_fire generation=%u ready=%d queued=%d active=%d", this, proxyHandshakeAdmissionGeneration, proxyHandshakeAdmissionReady ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0);
                requestPendingHostResolve();
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF) {
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                setProxyEndpointBackoffReady(true, "endpoint_backoff_timer_fire");
                setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "endpoint_backoff_timer_fire");
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_backoff_timer_fire generation=%u", this, proxyHandshakeAdmissionGeneration);
                if (!waitingForHostResolve.empty()) {
                    requestPendingHostResolve();
                    return;
                }
                openConnectionInternal(delayedIpv6);
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE) {
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                setProxyEndpointDnsCoalesceReady(true, "dns_coalesce_timer_fire");
                setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "dns_coalesce_timer_fire");
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_coalesce_timer_fire generation=%u", this, proxyHandshakeAdmissionGeneration);
                if (!waitingForHostResolve.empty()) {
                    bool cachedIpv6 = delayedIpv6;
                    std::string host = waitingForHostResolve;
                    bool blockedZeroAddress = false;
                    if (mtProxyEndpointUseCachedHostAddress(host, &cachedIpv6, &blockedZeroAddress)) {
                        setWaitingForHostResolve("", "dns_coalesce_cached_address");
                        setProxyEndpointDnsCoalesceReady(false, "dns_coalesce_cached_address");
                        openConnectionInternal(cachedIpv6);
                        return;
                    }
                    if (blockedZeroAddress) {
                        return;
                    }
                    setProxyEndpointDnsCoalesceReady(false, "dns_coalesce_request_pending");
                    requestPendingHostResolve();
                    return;
                }
                setProxyEndpointDnsCoalesceReady(false, "dns_coalesce_timer_fire");
                openConnectionInternal(delayedIpv6);
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE) {
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                setProxyEndpointTcpConnectGateState(-1, 1, -1, "tcp_connect_gate_timer_fire");
                setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "tcp_connect_gate_timer_fire");
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup tcp_connect_gate_timer_fire generation=%u", this, proxyHandshakeAdmissionGeneration);
                openConnectionInternal(delayedIpv6);
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
            if (mode == MT_PROXY_HANDSHAKE_TIMER_TLS_FRAME) {
                adjustWriteOp();
                return;
            }
            if (mode == MT_PROXY_HANDSHAKE_TIMER_ADMISSION) {
                bool delayedIpv6 = proxyHandshakeAdmissionIpv6;
                setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "admission_timer_fire");
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_timer_fire generation=%u ready=%d queued=%d active=%d", this, proxyHandshakeAdmissionGeneration, proxyHandshakeAdmissionReady ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0);
                openConnectionInternal(delayedIpv6);
            }
        });
    }

    proxyHandshakeAdmissionTimer->stop();
    proxyHandshakeAdmissionIpv6 = ipv6;
    proxyHandshakeAdmissionTimerMode = mode;
    proxyHandshakeAdmissionTimerGeneration = proxyHandshakeAdmissionGeneration;
    proxyHandshakeAdmissionTimer->setTimeout(delay, false);
    proxyHandshakeAdmissionTimer->start();
}

void ConnectionSocket::grantProxyHandshakeAdmission(bool ipv6, uint32_t generation, uint32_t delay, int32_t timerMode, const char *reason) {
    if (generation != proxyHandshakeAdmissionGeneration || socketFd < 0 || proxyAuthState < 10) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    setProxyHandshakeAdmissionState(0, 0, 1, 1, "admission_grant_queued");
    proxyHandshakeAdmissionStartTime = now;
    proxyHandshakeClientHelloSentTime = 0;
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_grant_queued admission_mode=%s connection_pattern=%s reason=%s key=%s priority=%d delay=%u", this, mtProxyConnectionPatternModeName(currentConnectionPatternMode), mtProxyConnectionPatternModeName(currentConnectionPatternMode), reason, proxyHandshakeAdmissionKey.c_str(), proxyHandshakeAdmissionPriority, delay);
    setTransportState(TransportState::WaitingGate, "admission_grant_queued");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::AdmissionQueue, now + delay, "admission_grant_queued");
    scheduleProxyHandshakeAdmissionTimer(delay, timerMode, ipv6);
}

void ConnectionSocket::cancelProxyHandshakeAdmission() {
    if (proxyHandshakeAdmissionActive) {
        releaseProxyHandshakeAdmission(false, "cancel");
    }
    mtProxyHandshakeSchedulerCancel(this);
    setProxyHandshakeAdmissionState(0, 0, 0, 0, "cancelProxyHandshakeAdmission");
    setProxyEndpointBackoffReady(false, "cancelProxyHandshakeAdmission");
    setProxyEndpointTcpConnectGateState(-1, 0, 0, "cancelProxyHandshakeAdmission");
    setProxyEndpointDnsCoalesceReady(false, "cancelProxyHandshakeAdmission");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "cancelProxyHandshakeAdmission");
    proxyHandshakeAdmissionIpv6 = false;
    proxyHandshakeAdmissionTimerMode = 0;
    proxyHandshakeAdmissionTimerGeneration = proxyHandshakeAdmissionGeneration;
    proxyHandshakeAdmissionGeneration++;
    proxyHandshakeAdmissionStartTime = 0;
    proxyHandshakeClientHelloSentTime = 0;
    proxyHandshakeAdmissionKey.clear();
    if (proxyHandshakeAdmissionTimer != nullptr) {
        proxyHandshakeAdmissionTimer->stop();
    }
}

void ConnectionSocket::releaseProxyHandshakeAdmission(bool succeeded, const char *reason) {
    checkProxyHandshakeAdmissionRelease(succeeded, reason);
    if (proxyHandshakeAdmissionKey.empty()) {
        setProxyHandshakeAdmissionState(0, 0, 0, 0, "admission_release_empty_key");
        return;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    int32_t connectionPatternMode = normalizeMtProxyConnectionPatternMode(currentConnectionPatternMode);
    bool hadAdmission = proxyHandshakeAdmissionActive || proxyHandshakeAdmissionQueued;
    bool wasActive = proxyHandshakeAdmissionActive;
    bool isNeutralSchedulerWaitRelease = reason != nullptr && strcmp(reason, "tcp_connect_gate_wait") == 0;
    bool isLifecycleHandshakeAbort = reason != nullptr && strcmp(reason, "background_handshake_aborted") == 0;
    bool isCancelRelease = reason != nullptr && strcmp(reason, "cancel") == 0;
    int64_t clientHelloElapsed = proxyHandshakeClientHelloSentTime > 0 ? now - proxyHandshakeClientHelloSentTime : 0;
    bool shouldApplyFreezeCooldown = wasActive && proxyHandshakeClientHelloSentTime > 0 && clientHelloElapsed >= MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS && !isLifecycleHandshakeAbort;
    bool shouldApplyTcpFailureCooldown = wasActive && !isNeutralSchedulerWaitRelease && startupTimeline.tcpConnectAttemptStarted() && proxyHandshakeClientHelloSentTime <= 0 && !isCancelRelease;
    bool suppressQueuedGrant = !succeeded && wasActive && !isNeutralSchedulerWaitRelease && !isLifecycleHandshakeAbort && proxyHandshakeClientHelloSentTime > 0 && !isCancelRelease;
    std::string admissionKey = proxyHandshakeAdmissionKey;
    MtProxyHandshakeReleaseRequest releaseRequest;
    releaseRequest.socket = this;
    releaseRequest.key = admissionKey;
    releaseRequest.hadAdmission = hadAdmission;
    releaseRequest.wasActive = wasActive;
    releaseRequest.succeeded = succeeded;
    releaseRequest.neutralSchedulerWaitRelease = isNeutralSchedulerWaitRelease;
    releaseRequest.lifecycleHandshakeAbort = isLifecycleHandshakeAbort;
    releaseRequest.suppressQueuedGrant = suppressQueuedGrant;
    releaseRequest.shouldApplyTcpFailureCooldown = shouldApplyTcpFailureCooldown;
    releaseRequest.shouldApplyFreezeCooldown = shouldApplyFreezeCooldown;
    releaseRequest.connectionPatternMode = connectionPatternMode;
    releaseRequest.now = now;
    MtProxyHandshakeReleaseDecision releaseDecision = mtProxyHandshakeSchedulerRelease(releaseRequest);

    if (releaseDecision.ignored && LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup admission_release_ignored admission_mode=%s connection_pattern=%s reason=%s success=%d key=%s", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, succeeded ? 1 : 0, admissionKey.c_str());
    }
    if (LOGS_ENABLED) {
        switch (releaseDecision.cooldownKind) {
            case MtProxyHandshakeCooldownKind::TcpFailure:
                DEBUG_D("connection(%p) mtproxy_startup admission_tcp_failure_cooldown admission_mode=%s connection_pattern=%s reason=%s key=%s penalty=%d cooldown_ms=%ld", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, admissionKey.c_str(), releaseDecision.cooldownPenalty, (long) releaseDecision.cooldownRemainingMs);
                break;
            case MtProxyHandshakeCooldownKind::Freeze:
                DEBUG_D("connection(%p) mtproxy_startup admission_freeze_cooldown admission_mode=%s connection_pattern=%s reason=%s key=%s penalty=%d cooldown_ms=%ld", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, admissionKey.c_str(), releaseDecision.cooldownPenalty, (long) releaseDecision.cooldownRemainingMs);
                break;
            case MtProxyHandshakeCooldownKind::Failure:
                DEBUG_D("connection(%p) mtproxy_startup admission_failure_cooldown admission_mode=%s connection_pattern=%s reason=%s key=%s penalty=%d cooldown_ms=%ld", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, admissionKey.c_str(), releaseDecision.cooldownPenalty, (long) releaseDecision.cooldownRemainingMs);
                break;
            case MtProxyHandshakeCooldownKind::FreezeObserved:
                DEBUG_D("connection(%p) mtproxy_startup admission_freeze_observed admission_mode=%s connection_pattern=%s reason=%s key=%s cooldown=disabled", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, admissionKey.c_str());
                break;
            case MtProxyHandshakeCooldownKind::None:
            default:
                break;
        }
    }
    if (releaseDecision.publishHoldPhase && LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup admission_hold_after_client_hello_failure admission_mode=%s connection_pattern=%s reason=%s key=%s queued=%d cooldown_ms=%ld", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, admissionKey.c_str(), releaseDecision.queuedCount, (long) releaseDecision.cooldownRemainingMs);
    }
    if (releaseDecision.hasNextRequest && LOGS_ENABLED) {
        DEBUG_D("mtproxy_startup admission_dequeue_global admission_mode=%s connection_pattern=%s key=%s request_class=%s active=%d queued=%d global_active=%d global_limit=%d priority=%d", mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), releaseDecision.nextRequest.key.c_str(), mtProxyRequestClassName(releaseDecision.nextRequest.requestClass), releaseDecision.nextRequest.endpointActive, releaseDecision.nextRequest.endpointQueued, releaseDecision.nextRequest.globalActive, releaseDecision.nextRequest.globalLimit, releaseDecision.nextRequest.priority);
    }

    if (releaseDecision.publishHoldPhase) {
        publishProxyConnectionStage("admission_hold_after_client_hello_failure");
    }

    setProxyHandshakeAdmissionState(0, 0, 0, 0, "admission_release");
    proxyHandshakeAdmissionStartTime = 0;
    proxyHandshakeClientHelloSentTime = 0;
    proxyHandshakeAdmissionTimerMode = 0;
    proxyHandshakeAdmissionTimerGeneration = proxyHandshakeAdmissionGeneration;
    proxyHandshakeAdmissionKey.clear();
    if (proxyHandshakeAdmissionTimer != nullptr) {
        proxyHandshakeAdmissionTimer->stop();
    }

    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup admission_release admission_mode=%s connection_pattern=%s reason=%s success=%d key=%s next=%d global_active=%d global_limit=%d", this, mtProxyConnectionPatternModeName(connectionPatternMode), mtProxyConnectionPatternModeName(connectionPatternMode), reason, succeeded ? 1 : 0, admissionKey.c_str(), releaseDecision.hasNextRequest ? 1 : 0, releaseDecision.globalActive, releaseDecision.globalLimit);
    if (releaseDecision.hasNextRequest && releaseDecision.nextRequest.socket != nullptr) {
        releaseDecision.nextRequest.socket->grantProxyHandshakeAdmission(releaseDecision.nextRequest.ipv6, releaseDecision.nextRequest.generation, releaseDecision.nextRequest.delayMs, releaseDecision.nextRequest.timerMode, reason);
    }
}

bool ConnectionSocket::scheduleMtProxyEndpointCircuitBreakerIfNeeded(bool ipv6) {
    if (!isCurrentMtProxyConnection() || (currentMtProxyEndpointKey.empty() && currentMtProxyNetworkEndpointKey.empty())) {
        return false;
    }
    int32_t connectionPatternMode = normalizeMtProxyConnectionPatternMode(currentConnectionPatternMode);
    if (proxyEndpointBackoffReady) {
        setProxyEndpointBackoffReady(false, "endpoint_backoff_ready_consumed");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "endpoint_backoff_ready_consumed");
        return false;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyEndpointPolicy::MtProxyEndpointContext context;
    context.endpointKey = currentMtProxyEndpointKey;
    context.recipeCacheKey = currentMtProxyRecipeCacheKey;
    context.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    context.connectionPatternMode = connectionPatternMode;
    context.priority = proxyHandshakeAdmissionPriority;
    MtProxyEndpointPolicy::CooldownResult cooldownResult = MtProxyEndpointPolicy::readCooldown(context, now);
    if (!cooldownResult.active) {
        return false;
    }

    uint32_t delay = mtProxyHandshakeSchedulerRetryDelay(now, cooldownResult.cooldownUntil, proxyHandshakeAdmissionPriority, connectionPatternMode);
    if (cooldownResult.remainingMs > 0 && (int64_t) delay < cooldownResult.remainingMs) {
        delay = (uint32_t) cooldownResult.remainingMs;
    }
    publishProxyConnectionStage("endpoint_cooldown");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_cooldown key=%s connection_pattern=%s priority=%d delay=%u cooldown_ms=%ld", this, cooldownResult.key.c_str(), mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionPriority, delay, (long) cooldownResult.remainingMs);
    setTransportState(TransportState::WaitingGate, "endpoint_cooldown");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::EndpointCooldown, now + delay, "endpoint_cooldown");
    scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF, ipv6);
    return true;
}

bool ConnectionSocket::mtProxyProbeBeginOrJoin(bool ipv6) {
    if (!isCurrentMtProxyConnection() || !currentSecretIsFakeTls || currentMtProxyProbeKey.empty()) {
        return false;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyProbeCoordinator::ProbeKey probeKey;
    probeKey.key = currentMtProxyProbeKey;
    probeKey.endpointKey = currentMtProxyEndpointKey;
    probeKey.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    probeKey.allowedSniVariants = currentAllowedSniVariants;
    MtProxyProbeCoordinator::Decision probeDecision = MtProxyProbeCoordinator::beginOrJoin(probeKey, mtProxyProbeOwnerToken, now);
    if (probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::ProfilesExhaustedBackoff) {
        proxyCheckDiagnostic = MtProxyPhase::HandshakeProfilesExhausted;
        MtProxySocketObservation observation;
        observation.phase = MtProxyPhase::HandshakeProfilesExhausted;
        observation.reason = "probe_profiles_exhausted";
        publishMtProxySocketObservation(observation);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_profiles_exhausted key=%s endpoint=%s owner_generation=%u", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), probeDecision.generation);
        closeSocket(1, -1);
        return true;
    }
    if (probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::JoinExisting) {
        proxyCheckDiagnostic = "mtproxy_probe_wait";
        publishProxyConnectionStage(proxyCheckDiagnostic.c_str());
        setTransportState(TransportState::WaitingGate, "mtproxy_probe_wait");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::ProbeWait, now + probeDecision.waitMs, "mtproxy_probe_wait");
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_join key=%s endpoint=%s owner_generation=%u wait_ms=%u", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), probeDecision.generation, probeDecision.waitMs);
        scheduleProxyHandshakeAdmissionTimer(probeDecision.waitMs, MT_PROXY_HANDSHAKE_TIMER_PROBE_WAIT, ipv6);
        return true;
    }
    if (probeDecision.kind == MtProxyProbeCoordinator::DecisionKind::UseWorkingRecipe) {
        currentRecipeFamily = probeDecision.workingCursor.family;
        currentRecipeSniVariant = probeDecision.workingCursor.sniVariant;
        currentRecipeParserVariant = probeDecision.workingCursor.parserVariant;
        currentRecipeClassicVariant = probeDecision.workingCursor.classicVariant;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_working_recipe key=%s endpoint=%s owner_generation=%u working_recipe=%s family=%s sni_variant=%s parser_variant=%s classic_variant=%s", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), probeDecision.generation, MtProxyAdaptivePolicy::recipeId(probeDecision.workingRecipe).c_str(), MtProxyAdaptivePolicy::clientHelloFamilyName(probeDecision.workingCursor.family), MtProxyAdaptivePolicy::sniVariantName(probeDecision.workingCursor.sniVariant), MtProxyAdaptivePolicy::parserVariantName(probeDecision.workingCursor.parserVariant), MtProxyAdaptivePolicy::classicVariantName(probeDecision.workingCursor.classicVariant));
    } else {
        acquireMtProxyProbeLease(probeDecision.ownerToken);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_start key=%s endpoint=%s generation=%u token=%llu", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), probeDecision.generation, (unsigned long long) probeDecision.ownerToken);
    }
    return false;
}

void ConnectionSocket::mtProxyProbeWaitTimerFire(bool ipv6) {
    if (!isCurrentMtProxyConnection() || currentMtProxyProbeKey.empty()) {
        return;
    }
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "probe_wait_timer_fire");
    setTransportState(TransportState::Prepared, "probe_wait_timer_fire");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_wait_timer_fire key=%s endpoint=%s", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str());
    openConnection(currentAddress, currentPort, "", ipv6, currentNetworkType, currentDatacenterId, currentMediaConnection);
}

void ConnectionSocket::acquireMtProxyProbeLease(uint64_t token) {
    releaseMtProxyProbeLease();
    mtProxyProbeOwnerToken = token;
    mtProxyProbeLeaseKey = currentMtProxyProbeKey;
    mtProxyProbeLeaseEndpointKey = currentMtProxyEndpointKey;
    mtProxyProbeLeaseNetworkEndpointKey = currentMtProxyNetworkEndpointKey;
    mtProxyProbeLeaseAllowedSni = currentAllowedSniVariants;
}

void ConnectionSocket::releaseMtProxyProbeLease() {
    // Key-independent ownership release: uses the probe key captured at acquire time, NOT the live
    // currentMtProxyProbeKey (which openConnection scrubs), so ownership can never leak on re-open or
    // non-FakeTLS teardown. Token-matched, so it can only ever free this connection's own entry.
    if (mtProxyProbeOwnerToken != 0 && !mtProxyProbeLeaseKey.empty()) {
        MtProxyProbeCoordinator::ProbeKey probeKey;
        probeKey.key = mtProxyProbeLeaseKey;
        probeKey.endpointKey = mtProxyProbeLeaseEndpointKey;
        probeKey.networkEndpointKey = mtProxyProbeLeaseNetworkEndpointKey;
        probeKey.allowedSniVariants = mtProxyProbeLeaseAllowedSni;
        MtProxyProbeCoordinator::cancelOwner(probeKey, mtProxyProbeOwnerToken);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup probe_owner_release key=%s token=%llu", this, mtProxyProbeLeaseKey.c_str(), (unsigned long long) mtProxyProbeOwnerToken);
    }
    mtProxyProbeOwnerToken = 0;
    mtProxyProbeLeaseKey.clear();
    mtProxyProbeLeaseEndpointKey.clear();
    mtProxyProbeLeaseNetworkEndpointKey.clear();
    mtProxyProbeLeaseAllowedSni = 0;
}

void ConnectionSocket::mtProxyProbeHeartbeat() {
    if (mtProxyProbeOwnerToken == 0 || currentMtProxyProbeKey.empty()) {
        return;
    }
    MtProxyProbeCoordinator::ProbeKey probeKey;
    probeKey.key = currentMtProxyProbeKey;
    probeKey.endpointKey = currentMtProxyEndpointKey;
    probeKey.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    probeKey.allowedSniVariants = currentAllowedSniVariants;
    MtProxyProbeCoordinator::touchOwner(probeKey, mtProxyProbeOwnerToken, ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis());
}

bool ConnectionSocket::scheduleMtProxyEndpointTcpConnectGateIfNeeded(bool ipv6) {
    if (!isCurrentMtProxyConnection() || currentMtProxyNetworkEndpointKey.empty()) {
        return false;
    }
    if (proxyEndpointTcpConnectActive) {
        return false;
    }
    bool wasReady = proxyEndpointTcpConnectReady;
    setProxyEndpointTcpConnectGateState(-1, 0, -1, "tcp_connect_gate_consume_ready");

    MtProxyEndpointPolicy::TcpConnectGateResult gateResult = MtProxyEndpointPolicy::beginTcpConnect(currentMtProxyNetworkEndpointKey, wasReady);
    if (!gateResult.shouldDelay) {
        setProxyEndpointTcpConnectGateState(1, -1, -1, "tcp_connect_gate_grant");
    }

    if (!gateResult.shouldDelay) {
        setProxyEndpointTcpConnectGateState(-1, -1, 0, "tcp_connect_gate_grant");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "tcp_connect_gate_grant");
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup tcp_connect_gate_grant key=%s active=%d ready=%d", this, currentMtProxyNetworkEndpointKey.c_str(), gateResult.activeTcpConnects, wasReady ? 1 : 0);
        return false;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    uint32_t delay = gateResult.delayMs;
    if (!proxyEndpointTcpConnectGatePublished) {
        setProxyEndpointTcpConnectGateState(-1, -1, 1, "tcp_connect_gate");
        publishProxyConnectionStage("tcp_connect_gate");
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup tcp_connect_gate key=%s active=%d delay=%u ready=%d", this, currentMtProxyNetworkEndpointKey.c_str(), gateResult.activeTcpConnects, delay, wasReady ? 1 : 0);
    } else if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup tcp_connect_gate_wait key=%s active=%d delay=%u ready=%d", this, currentMtProxyNetworkEndpointKey.c_str(), gateResult.activeTcpConnects, delay, wasReady ? 1 : 0);
    }
    setTransportState(TransportState::WaitingGate, "tcp_connect_gate");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::TcpConnectGate, now + delay, "tcp_connect_gate");
    if (proxyHandshakeAdmissionActive) {
        releaseProxyHandshakeAdmission(false, "tcp_connect_gate_wait");
    }
    scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE, ipv6);
    return true;
}

void ConnectionSocket::releaseMtProxyEndpointTcpConnect(const char *reason) {
    if (!proxyEndpointTcpConnectActive || currentMtProxyNetworkEndpointKey.empty()) {
        return;
    }
    int32_t activeTcpConnects = MtProxyEndpointPolicy::releaseTcpConnect(currentMtProxyNetworkEndpointKey);
    setProxyEndpointTcpConnectGateState(0, -1, 0, "tcp_connect_gate_release");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup tcp_connect_gate_release key=%s active=%d reason=%s", this, currentMtProxyNetworkEndpointKey.c_str(), activeTcpConnects, reason != nullptr ? reason : "unknown");
}

bool ConnectionSocket::scheduleMtProxyDnsCoalesceIfNeeded(bool ipv6) {
    if (!isCurrentMtProxyConnection() || currentMtProxyDnsCacheKey.empty()) {
        return false;
    }
    if (proxyEndpointDnsCoalesceReady) {
        setProxyEndpointDnsCoalesceReady(false, "dns_coalesce_ready_consumed");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "dns_coalesce_ready_consumed");
        return false;
    }

    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyEndpointPolicy::DnsCoalesceResult coalesceResult = MtProxyEndpointPolicy::beginDnsCoalesce(currentMtProxyDnsCacheKey, now);
    if (!coalesceResult.shouldDelay) {
        return false;
    }

    uint32_t delay = coalesceResult.delayMs;
    publishProxyConnectionStage("dns_coalesce_wait");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_coalesce_wait dns_key=%s delay=%u", this, currentMtProxyDnsCacheKey.c_str(), delay);
    setTransportState(TransportState::WaitingGate, "dns_coalesce_wait");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::DnsCoalesceWait, now + delay, "dns_coalesce_wait");
    scheduleProxyHandshakeAdmissionTimer(delay, MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE, ipv6);
    return true;
}

void ConnectionSocket::recordMtProxyEndpointFailure(const char *diagnostic, const char *reason) {
    if (!isCurrentMtProxyConnection() || (currentMtProxyEndpointKey.empty() && currentMtProxyNetworkEndpointKey.empty()) || diagnostic == nullptr || diagnostic[0] == '\0') {
        return;
    }
    if (mtProxyDiagnosticIsLocalSchedulerTimeout(diagnostic)) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_failure_skipped_local phase=%s reason=%s", this, diagnostic, reason != nullptr ? reason : "unknown");
        return;
    }
    std::string phase = diagnostic;
    size_t failureResponseBytes = bytesRead;
    MtProxyFailureEvidenceKind evidenceKind = mtProxyEvidenceForPhase(phase, failureResponseBytes);
    const char *failureEvidence = mtProxyFailureEvidenceName(evidenceKind);
    MtProxyRecoveryAction recoveryAction = mtProxyRecoveryActionForEvidence(evidenceKind);
    MtProxyDataPathFailureAction dataPathFailureAction = mtProxyDataPathFailureActionForPhase(phase, evidenceKind);
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    int32_t connectionPatternMode = normalizeMtProxyConnectionPatternMode(currentConnectionPatternMode);
    bool recipeFailure = currentSecretIsFakeTls
            && MtProxyProbeCoordinator::failureNeedsRecipe(phase)
            && mtProxyRecoveryActionAdvancesRecipe(recoveryAction);
    if (recipeFailure) {
        MtProxyProbeCoordinator::ProbeKey probeKey;
        probeKey.key = currentMtProxyProbeKey;
        probeKey.endpointKey = currentMtProxyEndpointKey;
        probeKey.networkEndpointKey = currentMtProxyNetworkEndpointKey;
        probeKey.allowedSniVariants = currentAllowedSniVariants;
        std::string failedRecipeId = currentMtProxyRecipeId();
        MtProxyAdaptivePolicy::RecipeCursor failedCursor;
        failedCursor.family = currentRecipeFamily;
        failedCursor.sniVariant = currentRecipeSniVariant;
        failedCursor.parserVariant = currentRecipeParserVariant;
        failedCursor.classicVariant = currentRecipeClassicVariant;
        MtProxyProbeCoordinator::FailureResult failure = MtProxyProbeCoordinator::completeFailure(
                probeKey,
                mtProxyProbeOwnerToken,
                phase,
                currentMtProxyRecipeUsesGrease(),
                currentMtProxyRecipeIsGreaseProbe(),
                mtProxyClassicFallbackAllowed(),
                now);
        if (!failure.recorded) {
            return;
        }
        std::string nextRecipeId = failure.recipeExhausted ? MtProxyPhase::HandshakeProfilesExhausted : mtProxyRecipeIdForCursor(failure.cursor);
        bool fallbackAllowed = !failure.recipeExhausted || mtProxyClassicFallbackAllowed();
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup recipe_failed key=%s recipe_key=%s endpoint_key=%s phase=%s reason=%s evidence=%s response_bytes=%zu recipe=%s recipe_id=%s family=%s sni_variant=%s parser_variant=%s classic_variant=%s next=%s next_recipe=%s next_family=%s next_sni_variant=%s next_parser_variant=%s next_classic_variant=%s fallback_allowed=%d classic_fallback_allowed=%d exhausted=%d owner_generation=%u cursor_generation=%u", this, currentMtProxyEndpointKey.c_str(), currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), phase.c_str(), reason != nullptr ? reason : "unknown", failureEvidence, failureResponseBytes, failedRecipeId.c_str(), failedRecipeId.c_str(), MtProxyAdaptivePolicy::clientHelloFamilyName(failedCursor.family), MtProxyAdaptivePolicy::sniVariantName(failedCursor.sniVariant), MtProxyAdaptivePolicy::parserVariantName(failedCursor.parserVariant), MtProxyAdaptivePolicy::classicVariantName(failedCursor.classicVariant), nextRecipeId.c_str(), nextRecipeId.c_str(), MtProxyAdaptivePolicy::clientHelloFamilyName(failure.cursor.family), MtProxyAdaptivePolicy::sniVariantName(failure.cursor.sniVariant), MtProxyAdaptivePolicy::parserVariantName(failure.cursor.parserVariant), MtProxyAdaptivePolicy::classicVariantName(failure.cursor.classicVariant), fallbackAllowed ? 1 : 0, mtProxyClassicFallbackAllowed() ? 1 : 0, failure.recipeExhausted ? 1 : 0, failure.generation, failure.cursor.generation);
        MtProxySocketObservation recipeFailureObservation;
        recipeFailureObservation.phase = "recipe_failed";
        recipeFailureObservation.reason = reason != nullptr ? reason : "unknown";
        recipeFailureObservation.endpointKey = currentMtProxyEndpointKey;
        recipeFailureObservation.probeKey = currentMtProxyProbeKey;
        recipeFailureObservation.networkEndpointKey = currentMtProxyNetworkEndpointKey;
        recipeFailureObservation.publishVisibleStage = false;
        publishMtProxySocketObservation(recipeFailureObservation);
        if (failure.recipeExhausted) {
            proxyCheckDiagnostic = MtProxyPhase::HandshakeProfilesExhausted;
            MtProxySocketObservation exhaustedObservation;
            exhaustedObservation.phase = MtProxyPhase::HandshakeProfilesExhausted;
            exhaustedObservation.reason = phase.c_str();
            exhaustedObservation.endpointKey = currentMtProxyEndpointKey;
            exhaustedObservation.probeKey = currentMtProxyProbeKey;
            exhaustedObservation.networkEndpointKey = currentMtProxyNetworkEndpointKey;
            publishMtProxySocketObservation(exhaustedObservation);
            MtProxyEndpointPolicy::MtProxyEndpointContext context;
            context.endpointKey = currentMtProxyEndpointKey;
            context.recipeCacheKey = currentMtProxyRecipeCacheKey;
            context.networkEndpointKey = currentMtProxyNetworkEndpointKey;
            context.fakeTls = currentSecretIsFakeTls;
            context.connectionPatternMode = connectionPatternMode;
            context.priority = proxyHandshakeAdmissionPriority;
            MtProxyEndpointPolicy::FailureResult exhaustedFailure = MtProxyEndpointPolicy::recordFailure(context, proxyCheckDiagnostic, now);
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup recipe_exhausted key=%s recipe_key=%s failed_phase=%s evidence=%s response_bytes=%zu next=handshake_profiles_exhausted exhausted_recorded=%d cooldown_ms=%ld cached_family=%s cached_sni_variant=%s cached_parser_variant=%s cached_classic_variant=%s classic_fallback_allowed=%d generation=%u", this, currentMtProxyEndpointKey.c_str(), currentMtProxyProbeKey.c_str(), phase.c_str(), failureEvidence, failureResponseBytes, exhaustedFailure.recorded ? 1 : 0, (long) exhaustedFailure.cooldownMs, MtProxyAdaptivePolicy::clientHelloFamilyName(failure.cachedCursor.family), MtProxyAdaptivePolicy::sniVariantName(failure.cachedCursor.sniVariant), MtProxyAdaptivePolicy::parserVariantName(failure.cachedCursor.parserVariant), MtProxyAdaptivePolicy::classicVariantName(failure.cachedCursor.classicVariant), mtProxyClassicFallbackAllowed() ? 1 : 0, failure.generation);
        }
        return;
    }
    if (dataPathFailureAction.dataPathShapingBackoff && LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_data shaping_failure phase=%s evidence=%s action=%s parser_variants=%d", this, phase.c_str(), failureEvidence, dataPathFailureAction.name, dataPathFailureAction.allowParserVariants ? 1 : 0);
    }
    MtProxyEndpointPolicy::MtProxyEndpointContext context;
    context.endpointKey = currentMtProxyEndpointKey;
    context.recipeCacheKey = currentMtProxyRecipeCacheKey;
    context.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    context.fakeTls = currentSecretIsFakeTls;
    context.connectionPatternMode = connectionPatternMode;
    context.priority = proxyHandshakeAdmissionPriority;
    std::string endpointFailurePhase = phase;
    MtProxyEndpointPolicy::FailureResult failure = MtProxyEndpointPolicy::recordFailure(context, endpointFailurePhase, now);
    if (!failure.recorded) {
        return;
    }
    if (failure.shadowedByUsableSuccess) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_failure_shadowed_by_success key=%s phase=%s reason=%s evidence=%s response_bytes=%zu connection_pattern=%s priority=%d hold_ms=%ld", this, failure.stateKey.c_str(), phase.c_str(), reason != nullptr ? reason : "unknown", failureEvidence, failureResponseBytes, mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionPriority, (long) failure.usableSuccessRemainingMs);
        return;
    }
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_failure key=%s phase=%s reason=%s evidence=%s response_bytes=%zu connection_pattern=%s priority=%d cooldown_ms=%ld", this, failure.stateKey.c_str(), phase.c_str(), reason != nullptr ? reason : "unknown", failureEvidence, failureResponseBytes, mtProxyConnectionPatternModeName(connectionPatternMode), proxyHandshakeAdmissionPriority, (long) failure.cooldownMs);
}

void ConnectionSocket::recordMtProxyEndpointHandshakeOk(const char *reason) {
    if (!isCurrentMtProxyConnection() || (currentMtProxyEndpointKey.empty() && currentMtProxyNetworkEndpointKey.empty())) {
        return;
    }
    MtProxyEndpointPolicy::MtProxyEndpointContext context;
    context.endpointKey = currentMtProxyEndpointKey;
    context.recipeCacheKey = currentMtProxyRecipeCacheKey;
    context.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    context.fakeTls = currentSecretIsFakeTls;
    MtProxyEndpointPolicy::recordHandshakeOk(context, reason);
    if (currentSecretIsFakeTls && !currentMtProxyProbeKey.empty()) {
        MtProxyProbeCoordinator::ProbeKey probeKey;
        probeKey.key = currentMtProxyProbeKey;
        probeKey.endpointKey = currentMtProxyEndpointKey;
        probeKey.networkEndpointKey = currentMtProxyNetworkEndpointKey;
        probeKey.allowedSniVariants = currentAllowedSniVariants;
        int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
        MtProxyProbeCoordinator::completeSuccess(probeKey, mtProxyProbeOwnerToken, reason, currentMtProxyRecipeUsesGrease(), currentMtProxyCompatibilityRecipe(), now);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup working_recipe_cached key=%s endpoint=%s reason=%s recipe=%s recipe_id=%s", this, currentMtProxyProbeKey.c_str(), currentMtProxyEndpointKey.c_str(), reason != nullptr ? reason : "unknown", currentMtProxyRecipeId().c_str(), currentMtProxyRecipeId().c_str());
    }
    std::string workingRecipeId = currentMtProxyRecipeId();
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_handshake_ok network_key=%s key=%s recipe_key=%s reason=%s working_recipe=%s recipe_id=%s", this, currentMtProxyNetworkEndpointKey.c_str(), currentMtProxyEndpointKey.c_str(), currentMtProxyRecipeCacheKey.c_str(), reason != nullptr ? reason : "unknown", workingRecipeId.c_str(), workingRecipeId.c_str());
}

void ConnectionSocket::recordMtProxyEndpointDataPathSuccess(const char *reason) {
    if (!isCurrentMtProxyConnection() || (currentMtProxyEndpointKey.empty() && currentMtProxyNetworkEndpointKey.empty())) {
        return;
    }
    if (reason == nullptr
            || (strcmp(reason, "first_tls_app_recv") != 0
                    && strcmp(reason, "first_mtproxy_packet_recv") != 0)) {
        logTransportInvariant("endpoint_data_path_success", "invalid_reason");
        if (LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_startup endpoint_data_path_success_rejected network_key=%s key=%s reason=%s", this, currentMtProxyNetworkEndpointKey.c_str(), currentMtProxyEndpointKey.c_str(), reason != nullptr ? reason : "unknown");
        }
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyEndpointPolicy::MtProxyEndpointContext context;
    context.endpointKey = currentMtProxyEndpointKey;
    context.recipeCacheKey = currentMtProxyRecipeCacheKey;
    context.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    context.fakeTls = currentSecretIsFakeTls;
    MtProxyEndpointPolicy::DataPathSuccessResult success = MtProxyEndpointPolicy::recordDataPathSuccess(context, reason, now);
    if (!success.accepted) {
        logTransportInvariant("endpoint_data_path_success", "policy_rejected");
        return;
    }
    if (currentSecretIsFakeTls && !currentMtProxyProbeKey.empty()) {
        MtProxyProbeCoordinator::ProbeKey probeKey;
        probeKey.key = currentMtProxyProbeKey;
        probeKey.endpointKey = currentMtProxyEndpointKey;
        probeKey.networkEndpointKey = currentMtProxyNetworkEndpointKey;
        probeKey.allowedSniVariants = currentAllowedSniVariants;
        MtProxyProbeCoordinator::completeSuccess(probeKey, mtProxyProbeOwnerToken, reason, currentMtProxyRecipeUsesGrease(), currentMtProxyCompatibilityRecipe(), now);
    }
    std::string workingRecipeId = currentMtProxyRecipeId();
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup endpoint_data_path_success network_key=%s key=%s recipe_key=%s reason=%s working_recipe=%s recipe_id=%s", this, currentMtProxyNetworkEndpointKey.c_str(), currentMtProxyEndpointKey.c_str(), currentMtProxyProbeKey.c_str(), reason != nullptr ? reason : "unknown", workingRecipeId.c_str(), workingRecipeId.c_str());
}

void ConnectionSocket::closeMtProxyDnsBlockedZeroAddress(const std::string &host, const std::string &ip, const char *reason) {
    setWaitingForHostResolve("", "dns_blocked_zero_address");
    setMtProxyDnsResolveAttemptStarted(false, "dns_blocked_zero_address");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "dns_blocked_zero_address");
    setProxyEndpointDnsCoalesceReady(false, "dns_blocked_zero_address");
    proxyCheckDiagnostic = MtProxyPhase::DnsBlockedZeroAddress;
    MtProxySocketObservation observation;
    observation.phase = MtProxyPhase::DnsBlockedZeroAddress;
    observation.reason = reason != nullptr ? reason : "unknown";
    publishMtProxySocketObservation(observation);
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_blocked_zero_address host=%s ip=%s reason=%s", this, host.c_str(), ip.c_str(), reason != nullptr ? reason : "unknown");
    closeSocket(1, -1);
}

bool ConnectionSocket::mtProxyEndpointUseCachedHostAddress(const std::string &host, bool *ipv6, bool *blockedZeroAddress) {
    if (blockedZeroAddress != nullptr) {
        *blockedZeroAddress = false;
    }
    if (!isCurrentMtProxyConnection() || currentMtProxyDnsCacheKey.empty()) {
        return false;
    }
    std::string cachedIpv4;
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyEndpointPolicy::useCachedHostAddress(currentMtProxyDnsCacheKey, now, &cachedIpv4);
    if (mtProxyIsBlockedZeroAddress(cachedIpv4)) {
        if (blockedZeroAddress != nullptr) {
            *blockedZeroAddress = true;
        }
        closeMtProxyDnsBlockedZeroAddress(host, cachedIpv4, "dns_cache_hit");
        return false;
    }
    if (cachedIpv4.empty() || inet_pton(AF_INET, cachedIpv4.c_str(), &socketAddress.sin_addr.s_addr) != 1) {
        return false;
    }
    if (ipv6 != nullptr) {
        *ipv6 = false;
    }
    publishProxyConnectionStage("dns_cache_hit");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_cache_hit dns_key=%s host=%s ip=%s", this, currentMtProxyDnsCacheKey.c_str(), host.c_str(), cachedIpv4.c_str());
    return true;
}

void ConnectionSocket::mtProxyEndpointStoreResolvedAddress(const std::string &host, const std::string &ip) {
    if (!isCurrentMtProxyConnection() || currentMtProxyDnsCacheKey.empty() || ip.empty()) {
        return;
    }
    if (mtProxyIsBlockedZeroAddress(ip)) {
        closeMtProxyDnsBlockedZeroAddress(host, ip, "dns_cache_store");
        return;
    }
    struct in_addr parsedAddress;
    if (inet_pton(AF_INET, ip.c_str(), &parsedAddress.s_addr) != 1) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyEndpointPolicy::storeResolvedAddress(currentMtProxyDnsCacheKey, ip, now);
    publishProxyConnectionStage("dns_cache_store");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_cache_store dns_key=%s host=%s ip=%s", this, currentMtProxyDnsCacheKey.c_str(), host.c_str(), ip.c_str());
}

MtProxyAdaptivePolicy::RecipeInput ConnectionSocket::currentMtProxyRecipeInput() {
    MtProxyAdaptivePolicy::RecipeInput input;
    input.fakeTls = currentSecretIsFakeTls;
    input.endpointKey = currentMtProxyRecipeCacheKey.empty() ? currentMtProxyEndpointKey : currentMtProxyRecipeCacheKey;
    input.sni = currentClientHelloSni.empty() ? currentSecretDomain : currentClientHelloSni;
    input.originalSni = currentOriginalSecretDomain;
    input.sanitizedSni = currentSanitizedSecretDomain.empty() ? currentSecretDomain : currentSanitizedSecretDomain;
    input.lowercaseAsciiSni = currentLowercaseSecretDomain.empty() ? currentSecretDomain : currentLowercaseSecretDomain;
    input.noTrailingDotSni = currentNoTrailingDotSecretDomain.empty() ? currentSecretDomain : currentNoTrailingDotSecretDomain;
    input.punycodeSni = currentPunycodeSecretDomain;
    input.allowedSniVariants = currentAllowedSniVariants;
    input.useRecipeCursor = true;
    input.cursor.family = currentRecipeFamily;
    input.cursor.sniVariant = currentRecipeSniVariant;
    input.cursor.parserVariant = currentRecipeParserVariant;
    input.cursor.classicVariant = currentRecipeClassicVariant;
    input.forceNoGrease = !MtProxyAdaptivePolicy::profileUsesGrease(currentEffectiveProxyTlsProfile);
    input.probeGrease = false;
    input.greaseSupported = false;
    input.recipeLevel = 0;
    input.alternateProfileIndex = 0;
    input.clientHelloFragmentation = currentClientHelloFragmentation;
    input.configuredTlsProfile = currentProxyTlsProfile;
    input.effectiveTlsProfile = currentEffectiveProxyTlsProfile;
    input.serverHelloParserMode = currentServerHelloParserMode;
    input.connectionPatternMode = currentConnectionPatternMode;
    input.recordSizingMode = currentRecordSizingMode;
    input.timingMode = currentTimingMode;
    input.startupCoverMode = currentStartupCoverMode;
    return input;
}

MtProxyAdaptivePolicy::CompatibilityRecipe ConnectionSocket::currentMtProxyCompatibilityRecipe() {
    if (!currentSecretIsFakeTls || currentMtProxyRecipeCacheKey.empty()) {
        return MtProxyAdaptivePolicy::CompatibilityRecipe();
    }
    MtProxyAdaptivePolicy::RecipeInput input = currentMtProxyRecipeInput();
    input.endpointKey = currentMtProxyRecipeCacheKey;
    input.lastDiagnostic = MtProxyProbeCoordinator::lastRecipeDiagnosticForProbe(currentMtProxyProbeKey);
    MtProxyProbeCoordinator::GreaseProbeResult greaseProbe = MtProxyProbeCoordinator::readGreaseProbeState(currentMtProxyProbeKey);
    input.forceNoGrease = !greaseProbe.useGrease;
    input.probeGrease = greaseProbe.probe;
    input.greaseSupported = greaseProbe.supported;
    return MtProxyAdaptivePolicy::recipeForCursor(input, input.cursor);
}

std::string ConnectionSocket::currentMtProxyRecipeId() {
    if (!currentSecretIsFakeTls || currentMtProxyRecipeCacheKey.empty()) {
        return "";
    }
    return MtProxyAdaptivePolicy::recipeId(currentMtProxyCompatibilityRecipe());
}

std::string ConnectionSocket::mtProxyRecipeIdForCursor(const MtProxyAdaptivePolicy::RecipeCursor &cursor) {
    if (!currentSecretIsFakeTls || currentMtProxyRecipeCacheKey.empty()) {
        return "";
    }
    MtProxyAdaptivePolicy::RecipeInput input = currentMtProxyRecipeInput();
    input.endpointKey = currentMtProxyRecipeCacheKey;
    input.cursor = cursor;
    input.lastDiagnostic = MtProxyProbeCoordinator::lastRecipeDiagnosticForProbe(currentMtProxyProbeKey);
    MtProxyProbeCoordinator::GreaseProbeResult greaseProbe = MtProxyProbeCoordinator::readGreaseProbeState(currentMtProxyProbeKey);
    input.forceNoGrease = !greaseProbe.useGrease;
    input.probeGrease = greaseProbe.probe;
    input.greaseSupported = greaseProbe.supported;
    return MtProxyAdaptivePolicy::recipeId(MtProxyAdaptivePolicy::recipeForCursor(input, cursor));
}

bool ConnectionSocket::currentMtProxyRecipeUsesGrease() {
    return currentSecretIsFakeTls && MtProxyAdaptivePolicy::profileUsesGrease(currentEffectiveProxyTlsProfile);
}

bool ConnectionSocket::currentMtProxyRecipeIsGreaseProbe() {
    if (!currentMtProxyRecipeUsesGrease() || currentMtProxyRecipeCacheKey.empty()) {
        return false;
    }
    MtProxyProbeCoordinator::GreaseProbeResult greaseProbe = MtProxyProbeCoordinator::readGreaseProbeState(currentMtProxyProbeKey);
    return greaseProbe.probe;
}

bool ConnectionSocket::mtProxyClassicFallbackAllowed() {
    // ee secrets are SNI/HMAC-bound FakeTLS recipes; do not synthesize a classic secret from them.
    return !currentSecretIsFakeTls
           && currentSecretKind != nullptr
           && (strcmp(currentSecretKind, "legacy") == 0 || strcmp(currentSecretKind, "dd") == 0);
}

void ConnectionSocket::applyMtProxyPhaseAdaptiveRecipe() {
    if (!currentSecretIsFakeTls || currentMtProxyRecipeCacheKey.empty()) {
        return;
    }
    MtProxyAdaptivePolicy::RecipeCursor cursor = MtProxyProbeCoordinator::recipeCursorForProbe(currentMtProxyProbeKey);
    MtProxyProbeCoordinator::GreaseProbeResult greaseProbe = MtProxyProbeCoordinator::readGreaseProbeState(currentMtProxyProbeKey);
    MtProxyAdaptivePolicy::RecipeInput input = currentMtProxyRecipeInput();
    input.endpointKey = currentMtProxyRecipeCacheKey;
    input.sni = currentSecretDomain;
    input.cursor = cursor;
    input.forceNoGrease = !greaseProbe.useGrease;
    input.probeGrease = greaseProbe.probe;
    input.greaseSupported = greaseProbe.supported;
    input.lastDiagnostic = MtProxyProbeCoordinator::lastRecipeDiagnosticForProbe(currentMtProxyProbeKey);
    MtProxyHandshakePlan plan = mtProxyBuildHandshakePlan(input, cursor, currentMtProxyEndpointKey, currentMtProxyProbeKey);
    currentRecipeFamily = plan.cursor.family;
    currentRecipeSniVariant = plan.cursor.sniVariant;
    currentRecipeParserVariant = plan.cursor.parserVariant;
    currentRecipeClassicVariant = plan.cursor.classicVariant;
    currentClientHelloFragmentation = plan.clientHelloFragmentation;
    currentEffectiveProxyTlsProfile = plan.tlsProfile;
    currentServerHelloParserMode = plan.serverHelloParserMode;
    currentClientHelloSni = plan.clientHelloSni;
    currentConnectionPatternMode = plan.recipe.connectionPatternMode;
    currentRecordSizingMode = plan.recordSizingMode;
    currentTimingMode = plan.timingMode;
    currentStartupCoverMode = plan.startupCoverMode;
    publishProxyConnectionStage("phase_adaptive_recipe");
    const MtProxyAdaptivePolicy::CompatibilityRecipe &descriptor = plan.recipe;
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup phase_adaptive_recipe key=%s recipe_key=%s family=%s sni_variant=%s parser_variant=%s classic_variant=%s last=%s client_hello_sni=%s fragment=%d effective_profile=%s connection_pattern=%s record_sizing=%d timing=%d startup_cover=%d recipe=%s recipe_id=%s server_hello_parser=%s grease_probe=%d grease_supported=%d grease_rejected=%d experimental_no_sni=%d cursor_generation=%u", this, currentMtProxyEndpointKey.c_str(), currentMtProxyRecipeCacheKey.c_str(), descriptor.familyName.c_str(), descriptor.sniVariantName.c_str(), descriptor.parserVariantName.c_str(), descriptor.classicVariantName.c_str(), input.lastDiagnostic.c_str(), currentClientHelloSni.empty() ? "none" : currentClientHelloSni.c_str(), currentClientHelloFragmentation, mtProxyTlsProfileName(currentEffectiveProxyTlsProfile), mtProxyConnectionPatternModeName(currentConnectionPatternMode), currentRecordSizingMode, currentTimingMode, currentStartupCoverMode, plan.recipeId.c_str(), plan.recipeId.c_str(), mtProxyServerHelloParserName(currentServerHelloParserMode), plan.greaseProbe ? 1 : 0, plan.greaseSupported ? 1 : 0, greaseProbe.rejected ? 1 : 0, descriptor.experimentalNoSni ? 1 : 0, plan.cursor.generation);
}

void ConnectionSocket::markProxyHandshakeClientHelloSent() {
    if (!proxyHandshakeAdmissionActive || proxyHandshakeAdmissionKey.empty()) {
        return;
    }
    proxyHandshakeClientHelloSentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    scheduleProxyHandshakeAdmissionTimer((uint32_t) MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS, MT_PROXY_HANDSHAKE_TIMER_FREEZE, proxyHandshakeAdmissionIpv6);
}

bool ConnectionSocket::didPauseDuringProxyServerHelloWait(int64_t now) {
    if (proxyHandshakeClientHelloSentTime == 0) {
        return false;
    }
    int64_t pauseTime = ConnectionsManager::getInstance(instanceNum).lastMonotonicPauseTime;
    return pauseTime != 0 && pauseTime >= proxyHandshakeClientHelloSentTime && pauseTime <= now;
}

void ConnectionSocket::markProxyHandshakeFreezeIfNeeded() {
    if (!proxyHandshakeAdmissionActive || proxyHandshakeClientHelloSentTime == 0 || proxyAuthState != 11) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    int64_t elapsed = now - proxyHandshakeClientHelloSentTime;
    if (elapsed >= MT_PROXY_HANDSHAKE_FREEZE_TIMEOUT_MS) {
        bool pausedDuringHandshake = didPauseDuringProxyServerHelloWait(now);
        int64_t pauseTime = ConnectionsManager::getInstance(instanceNum).lastMonotonicPauseTime;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup faketls_server_hello_wait_timeout connection_pattern=%s key=%s elapsed=%ld background_pause=%d pause_age_ms=%ld", this, mtProxyConnectionPatternModeName(currentConnectionPatternMode), proxyHandshakeAdmissionKey.c_str(), (long) elapsed, pausedDuringHandshake ? 1 : 0, pausedDuringHandshake ? (long) (now - pauseTime) : -1L);
        releaseProxyHandshakeAdmission(false, pausedDuringHandshake ? "background_handshake_aborted" : "freeze_timeout");
        if (MT_PROXY_HANDSHAKE_CLOSE_ON_FREEZE_ENABLED) {
            if (pausedDuringHandshake) {
                proxyCheckDiagnostic = "background_handshake_aborted";
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup background_handshake_aborted elapsed=%ld pause_age_ms=%ld", this, (long) elapsed, (long) (now - pauseTime));
            } else if (serverHelloHmacMismatchObserved) {
                proxyCheckDiagnostic = MtProxyPhase::ServerHelloHmacMismatch;
                tlsHashMismatch = true;
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_timeout bytes=%zu", this, bytesRead);
            } else if (bytesRead == 0) {
                proxyCheckDiagnostic = MtProxyPhase::FaketlsServerHelloWaitTimeout;
            } else {
                logMtProxyTlsAfterClientHello(bytesRead);
                proxyCheckDiagnostic = classifyMtProxyPostClientHelloResponse(bytesRead);
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
        proxyCheckDiagnostic = MtProxyPhase::ServerHelloHmacMismatch;
        tlsHashMismatch = true;
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_timeout bytes=%zu elapsed=%ld", this, bytesRead, (long) elapsed);
        closeSocket(1, ETIMEDOUT);
    }
}

const char *ConnectionSocket::getProxyCheckDiagnostic() {
    return proxyCheckDiagnostic.empty() ? "unknown_fail" : proxyCheckDiagnostic.c_str();
}

bool ConnectionSocket::isProxyCloseDiagnosticSuppressed() {
    return proxyCloseDiagnosticSuppressed;
}

bool ConnectionSocket::isClosingOrClosedForWrites() const {
    return socketDeadForWrites
            || socketCloseNotified
            || currentTransportState == TransportState::Closing;
}

const char *ConnectionSocket::transportStateName(TransportState state) {
    return stateMachine.lifecycleName(state);
}

bool ConnectionSocket::isAllowedTransportTransition(TransportState previous, TransportState next) {
    return stateMachine.isAllowedTransition(previous, next);
}

void ConnectionSocket::setTransportState(TransportState next, const char *reason) {
    if (currentTransportState == next) {
        return;
    }
    const char *previous = transportStateName(currentTransportState);
    if (!isAllowedTransportTransition(currentTransportState, next)) {
        logTransportInvariant("setTransportState", "invalid_transition");
    }
    stateMachine.setLifecycle(next);
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport state_change from=%s to=%s reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, previous, transportStateName(next), reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

const char *ConnectionSocket::proxyAuthStateName(uint8_t state) {
    switch (state) {
        case 0:
            return "ready";
        case 1:
            return "socks_method_send";
        case 2:
            return "socks_method_wait";
        case 3:
            return "socks_auth_send";
        case 4:
            return "socks_auth_wait";
        case 5:
            return "socks_connect_send";
        case 6:
            return "socks_connect_wait";
        case 10:
            return "faketls_prepare";
        case 11:
            return "faketls_client_hello";
        default:
            return "unknown";
    }
}

bool ConnectionSocket::isAllowedProxyAuthTransition(uint8_t previous, uint8_t next) {
    if (previous == next) {
        return true;
    }
    if (next == 0) {
        return true;
    }
    struct ProxyAuthTransitionRule {
        uint8_t previous;
        uint8_t next;
    };
    static const ProxyAuthTransitionRule allowedTransitions[] = {
            {0, 1},
            {0, 10},
            {1, 2},
            {2, 3},
            {2, 5},
            {3, 4},
            {4, 5},
            {5, 6},
            {10, 11},
    };
    for (const ProxyAuthTransitionRule &rule : allowedTransitions) {
        if (rule.previous == previous && rule.next == next) {
            return true;
        }
    }
    return false;
}

void ConnectionSocket::setProxyAuthState(uint8_t next, const char *reason) {
    if (proxyAuthState == next) {
        return;
    }
    const char *previous = proxyAuthStateName(proxyAuthState);
    if (!isAllowedProxyAuthTransition(proxyAuthState, next)) {
        logTransportInvariant("setProxyAuthState", "invalid_transition");
    }
    stateMachine.setProxyAuthState(next);
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport proxy_state_change from=%s to=%s reason=%s proxy_state_from=%s proxy_state_to=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, previous, proxyAuthStateName(next), reason != nullptr ? reason : "unknown", previous, proxyAuthStateName(next), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

const char *ConnectionSocket::tlsStateName(int8_t state) {
    switch (state) {
        case 0:
            return "plain_or_inactive";
        case 1:
            return "faketls_ready";
        case 2:
            return "faketls_appdata";
        default:
            return "unknown";
    }
}

bool ConnectionSocket::isAllowedTlsStateTransition(int8_t previous, int8_t next) {
    if (previous == next) {
        return true;
    }
    if (next == 0) {
        return true;
    }
    struct TlsStateTransitionRule {
        int8_t previous;
        int8_t next;
    };
    static const TlsStateTransitionRule allowedTransitions[] = {
            {0, 1},
            {1, 2},
    };
    for (const TlsStateTransitionRule &rule : allowedTransitions) {
        if (rule.previous == previous && rule.next == next) {
            return true;
        }
    }
    return false;
}

void ConnectionSocket::setTlsState(int8_t next, const char *reason) {
    if (tlsState == next) {
        return;
    }
    const char *previous = tlsStateName(tlsState);
    if (!isAllowedTlsStateTransition(tlsState, next)) {
        logTransportInvariant("setTlsState", "invalid_transition");
    }
    stateMachine.setTlsState(next);
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport tls_state_change from=%s to=%s reason=%s tls_state_from=%s tls_state_to=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, previous, tlsStateName(next), reason != nullptr ? reason : "unknown", previous, tlsStateName(next), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::logTransportSnapshot(const char *event, const char *reason) {
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport snapshot event=%s reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, event != nullptr ? event : "unknown", reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::logTransportInvariant(const char *action, const char *reason) {
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport transport_invariant action=%s reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, action != nullptr ? action : "unknown", reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

const ConnectionSocket::TransportActionRule *ConnectionSocket::findTransportActionRule(const char *action) {
    return stateMachine.findActionRule(action);
}

bool ConnectionSocket::isTransportStateAllowedForAction(const char *action) {
    return findTransportActionRule(action) != nullptr;
}

bool ConnectionSocket::checkTransportActionRequirements(const char *action) {
    const TransportActionRule *rule = findTransportActionRule(action);
    if (rule == nullptr) {
        logTransportInvariant(action, "invalid_state");
        return false;
    }
    if (rule->socketPolicy == TransportSocketPolicy::LiveEpoll && !canUseLiveEpollSocket(action)) {
        return false;
    }
    if (rule->socketPolicy == TransportSocketPolicy::NoSocket) {
        if (socketFd >= 0) {
            logTransportInvariant(action, "socket_already_open");
            return false;
        }
        if (epollRegistered) {
            logTransportInvariant(action, "epoll_already_registered");
            return false;
        }
    }
    if (rule->socketPolicy == TransportSocketPolicy::OpenWithoutEpoll) {
        if (socketFd < 0) {
            logTransportInvariant(action, "socket_closed");
            return false;
        }
        if (epollRegistered) {
            logTransportInvariant(action, "epoll_already_registered");
            return false;
        }
    }
    if (rule->expectedProxyAuthState >= 0 && proxyAuthState != (uint8_t) rule->expectedProxyAuthState) {
        logTransportInvariant(action, "invalid_proxy_state");
        return false;
    }
    if (rule->expectedTlsState >= 0 && tlsState != rule->expectedTlsState) {
        logTransportInvariant(action, "invalid_tls_state");
        return false;
    }
    if (rule->requireWssTransport) {
        if (!currentTransportWss) {
            logTransportInvariant(action, "not_wss");
            return false;
        }
        if (currentWssTransport == nullptr) {
            logTransportInvariant(action, "missing_transport");
            return false;
        }
    }
    if (rule->requireWssReady && (currentWssTransport == nullptr || !currentWssTransport->isReady())) {
        logTransportInvariant(action, "wss_not_ready");
        return false;
    }
    return true;
}

void ConnectionSocket::setSocketFd(int fd, const char *reason) {
    int previousOpen = socketFd >= 0 ? 1 : 0;
    if (!stateMachine.setSocketFd(fd)) {
        return;
    }
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport socket_fd_state_change open=%d previous_open=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, socketFd >= 0 ? 1 : 0, previousOpen, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setEpollRegistered(bool registered, const char *reason) {
    if (!stateMachine.setEpollRegistered(registered)) {
        return;
    }
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport epoll_registration_state_change registered=%d reason=%s epoll_registered=%d transport_state=%s admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, registered ? 1 : 0, reason != nullptr ? reason : "unknown", epollRegistered ? 1 : 0, transportStateName(currentTransportState), proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

bool ConnectionSocket::canCreateSocket(const char *action) {
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canUseLiveEpollSocket(const char *action) {
    if (socketFd < 0) {
        logTransportInvariant(action, "socket_closed");
        return false;
    }
    if (!epollRegistered) {
        logTransportInvariant(action, "epoll_not_registered");
        return false;
    }
    return true;
}

bool ConnectionSocket::canModifyEpollWriteInterest(const char *action) {
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canSendPendingClientHello() {
    return checkTransportActionRequirements("sendPendingClientHello");
}

bool ConnectionSocket::canSendPendingTlsFrame() {
    return checkTransportActionRequirements("sendPendingTlsFrame");
}

bool ConnectionSocket::canSendSocksHandshakeFrame(const char *action, uint8_t expectedProxyAuthState) {
    const TransportActionRule *rule = findTransportActionRule(action);
    if (rule != nullptr && rule->expectedProxyAuthState >= 0 && rule->expectedProxyAuthState != expectedProxyAuthState) {
        logTransportInvariant(action, "proxy_state_policy_mismatch");
        return false;
    }
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canSendPlainMtProtoPayload() {
    return checkTransportActionRequirements("sendPlainMtProtoPayload");
}

bool ConnectionSocket::canStartTcpConnect() {
    return checkTransportActionRequirements("connect");
}

bool ConnectionSocket::canRegisterEpollSocket() {
    return checkTransportActionRequirements("epoll_ctl_add");
}

bool ConnectionSocket::canConfigureOpenSocket() {
    return checkTransportActionRequirements("configure_socket");
}

bool ConnectionSocket::canCheckSocketError() {
    return checkTransportActionRequirements("checkSocketError");
}

bool ConnectionSocket::canProcessEpollEvent() {
    return checkTransportActionRequirements("onEvent");
}

void ConnectionSocket::checkCloseSocketAction(const char *action) {
    checkTransportActionRequirements(action);
}

bool ConnectionSocket::canUnregisterEpollSocket() {
    return checkTransportActionRequirements("epoll_ctl_del");
}

bool ConnectionSocket::canCloseNativeSocket() {
    return checkTransportActionRequirements("close_native_socket");
}

void ConnectionSocket::setProxyHandshakeAdmissionState(int8_t queued, int8_t published, int8_t active, int8_t ready, const char *reason) {
    bool nextQueued = queued >= 0 ? queued != 0 : proxyHandshakeAdmissionQueued;
    bool nextPublished = published >= 0 ? published != 0 : proxyHandshakeAdmissionQueuePublished;
    bool nextActive = active >= 0 ? active != 0 : proxyHandshakeAdmissionActive;
    bool nextReady = ready >= 0 ? ready != 0 : proxyHandshakeAdmissionReady;
    if (proxyHandshakeAdmissionQueued == nextQueued
            && proxyHandshakeAdmissionQueuePublished == nextPublished
            && proxyHandshakeAdmissionActive == nextActive
            && proxyHandshakeAdmissionReady == nextReady) {
        return;
    }
    proxyHandshakeAdmissionQueued = nextQueued;
    proxyHandshakeAdmissionQueuePublished = nextPublished;
    proxyHandshakeAdmissionActive = nextActive;
    proxyHandshakeAdmissionReady = nextReady;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport admission_state_change queued=%d published=%d active=%d ready=%d reason=%s admission_active=%d admission_queued=%d transport_state=%s epoll_registered=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, proxyHandshakeAdmissionQueued ? 1 : 0, proxyHandshakeAdmissionQueuePublished ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionReady ? 1 : 0, reason != nullptr ? reason : "unknown", proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::checkProxyHandshakeAdmissionRelease(bool succeeded, const char *reason) {
    if (!proxyHandshakeAdmissionActive && !proxyHandshakeAdmissionQueued) {
        return;
    }
    if (checkTransportActionRequirements("releaseProxyHandshakeAdmission")) {
        return;
    }
    logTransportInvariant("releaseProxyHandshakeAdmission", succeeded ? "unexpected_success_state" : "unexpected_failure_state");
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport admission_release_invariant reason=%s success=%d transport_state=%s admission_active=%d admission_queued=%d", this, reason != nullptr ? reason : "unknown", succeeded ? 1 : 0, transportStateName(currentTransportState), proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0);
    }
}

void ConnectionSocket::setProxyEndpointTcpConnectGateState(int8_t active, int8_t ready, int8_t published, const char *reason) {
    bool nextActive = active >= 0 ? active != 0 : proxyEndpointTcpConnectActive;
    bool nextReady = ready >= 0 ? ready != 0 : proxyEndpointTcpConnectReady;
    bool nextPublished = published >= 0 ? published != 0 : proxyEndpointTcpConnectGatePublished;
    if (proxyEndpointTcpConnectActive == nextActive
            && proxyEndpointTcpConnectReady == nextReady
            && proxyEndpointTcpConnectGatePublished == nextPublished) {
        return;
    }
    proxyEndpointTcpConnectActive = nextActive;
    proxyEndpointTcpConnectReady = nextReady;
    proxyEndpointTcpConnectGatePublished = nextPublished;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport tcp_connect_gate_state_change active=%d ready=%d published=%d reason=%s tcp_gate_active=%d transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, proxyEndpointTcpConnectActive ? 1 : 0, proxyEndpointTcpConnectReady ? 1 : 0, proxyEndpointTcpConnectGatePublished ? 1 : 0, reason != nullptr ? reason : "unknown", proxyEndpointTcpConnectActive ? 1 : 0, transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setProxyEndpointBackoffReady(bool ready, const char *reason) {
    if (proxyEndpointBackoffReady == ready) {
        return;
    }
    proxyEndpointBackoffReady = ready;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport endpoint_backoff_ready_state_change ready=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, proxyEndpointBackoffReady ? 1 : 0, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setProxyEndpointDnsCoalesceReady(bool ready, const char *reason) {
    if (proxyEndpointDnsCoalesceReady == ready) {
        return;
    }
    proxyEndpointDnsCoalesceReady = ready;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport dns_coalesce_ready_state_change ready=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, proxyEndpointDnsCoalesceReady ? 1 : 0, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setAdjustWriteOpAfterResolve(bool pending, const char *reason) {
    if (adjustWriteOpAfterResolve == pending) {
        return;
    }
    adjustWriteOpAfterResolve = pending;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport write_after_resolve_state_change pending=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, adjustWriteOpAfterResolve ? 1 : 0, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setAdjustWriteOpAfterPreTcpGate(bool pending, const char *reason) {
    if (adjustWriteOpAfterPreTcpGate == pending) {
        return;
    }
    adjustWriteOpAfterPreTcpGate = pending;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport write_after_pre_tcp_gate_state_change pending=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, adjustWriteOpAfterPreTcpGate ? 1 : 0, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setMtProxyTcpConnectAttemptStarted(bool started, const char *reason) {
    if (startupTimeline.tcpConnectAttemptStarted() == started) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    if (started) {
        startupTimeline.beginTcpConnect(now, timeout);
        lastEventTime = now;
    } else {
        startupTimeline.finishTcpConnect();
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport tcp_connect_attempt_started_state_change started=%d reason=%s tcp_start_ms=%lld tcp_deadline_ms=%lld transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, startupTimeline.tcpConnectAttemptStarted() ? 1 : 0, reason != nullptr ? reason : "unknown", (long long) startupTimeline.tcpConnectStartTimeMs(), (long long) startupTimeline.tcpConnectDeadlineMs(), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setMtProxyDnsResolveAttemptStarted(bool started, const char *reason) {
    if (startupTimeline.dnsResolveAttemptStarted() == started) {
        return;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    if (started) {
        startupTimeline.beginDnsResolve(now, timeout);
    } else {
        startupTimeline.finishDnsResolve();
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport dns_resolve_attempt_started_state_change started=%d reason=%s dns_start_ms=%lld dns_deadline_ms=%lld transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, startupTimeline.dnsResolveAttemptStarted() ? 1 : 0, reason != nullptr ? reason : "unknown", (long long) startupTimeline.dnsResolveStartTimeMs(), (long long) startupTimeline.dnsResolveDeadlineMs(), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setMtProxyPreTcpWaitPhase(MtProxyStartupPhase phase, int64_t deadlineMs, const char *reason) {
    MtProxyStartupPhase previousPhase = startupTimeline.phase();
    int64_t previousDeadline = startupTimeline.localWaitDeadlineMs();
    if (phase == MtProxyStartupPhase::None) {
        startupTimeline.finishLocalWait();
    } else {
        startupTimeline.beginLocalWait(phase, deadlineMs);
    }
    if (previousPhase == startupTimeline.phase() && previousDeadline == startupTimeline.localWaitDeadlineMs()) {
        return;
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport pre_tcp_wait_state_change phase=%s deadline_ms=%lld reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, startupTimeline.phaseName(), (long long) startupTimeline.localWaitDeadlineMs(), reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::finishMtProxyPreTcpWait(const char *reason) {
    if (!isCurrentMtProxyConnection()) {
        return;
    }
    startupTimeline.finishLocalWait();
    proxyHandshakeAdmissionTimerMode = 0;
    proxyHandshakeAdmissionTimerGeneration = proxyHandshakeAdmissionGeneration;
    proxyHandshakeAdmissionGeneration++;
    if (proxyHandshakeAdmissionTimer != nullptr) {
        proxyHandshakeAdmissionTimer->stop();
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup pre_tcp_wait_finished reason=%s generation=%u transport_state=%s epoll_registered=%d tcp_started=%d", this, reason != nullptr ? reason : "unknown", proxyHandshakeAdmissionGeneration, transportStateName(currentTransportState), epollRegistered ? 1 : 0, startupTimeline.tcpConnectAttemptStarted() ? 1 : 0);
    }
}

MtProxyStartupTimerKind ConnectionSocket::mtProxyStartupTimerKindForMode(int32_t mode) {
    switch (mode) {
        case MT_PROXY_HANDSHAKE_TIMER_ADMISSION:
            return MtProxyStartupTimerKind::Admission;
        case MT_PROXY_HANDSHAKE_TIMER_HOST_RESOLVE:
            return MtProxyStartupTimerKind::HostResolveAdmission;
        case MT_PROXY_HANDSHAKE_TIMER_ENDPOINT_BACKOFF:
            return MtProxyStartupTimerKind::EndpointBackoff;
        case MT_PROXY_HANDSHAKE_TIMER_DNS_COALESCE:
            return MtProxyStartupTimerKind::DnsCoalesce;
        case MT_PROXY_HANDSHAKE_TIMER_TCP_CONNECT_GATE:
            return MtProxyStartupTimerKind::TcpConnectGate;
        default:
            return MtProxyStartupTimerKind::None;
    }
}

bool ConnectionSocket::canRunMtProxyPreTcpTimer(MtProxyStartupTimerKind expectedKind, uint32_t timerGeneration) {
    MtProxyStartupTimerDecision decision = startupTimeline.canRunPreTcpTimer(expectedKind,
            timerGeneration,
            proxyHandshakeAdmissionGeneration,
            mtProxyStartupTimerKindForMode(proxyHandshakeAdmissionTimerMode),
            socketFd >= 0,
            currentTransportState == TransportState::WaitingGate,
            epollRegistered);
    if (decision.canRun) {
        return true;
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup pre_tcp_timer_ignored reason=%s mode=%s timer_mode=%s generation=%u current_generation=%u transport_state=%s epoll_registered=%d dns_started=%d tcp_started=%d socket_fd=%d", this, decision.ignoreReason != nullptr ? decision.ignoreReason : "unknown", MtProxyStartupTimeline::timerKindName(expectedKind), MtProxyStartupTimeline::timerKindName(mtProxyStartupTimerKindForMode(proxyHandshakeAdmissionTimerMode)), timerGeneration, proxyHandshakeAdmissionGeneration, transportStateName(currentTransportState), epollRegistered ? 1 : 0, startupTimeline.dnsResolveAttemptStarted() ? 1 : 0, startupTimeline.tcpConnectAttemptStarted() ? 1 : 0, socketFd);
    }
    return false;
}

void ConnectionSocket::classifyMtProxyPreTcpTimeoutDiagnostic(const char *reason) {
    if (!isCurrentMtProxyConnection()) {
        return;
    }
    if (currentTransportState != TransportState::Prepared && currentTransportState != TransportState::WaitingGate && currentTransportState != TransportState::TcpConnecting) {
        return;
    }
    std::string previousDiagnostic = proxyCheckDiagnostic;
    const char *diagnostic = startupTimeline.terminalDiagnostic(mtproxySocketConnectedLogged);
    if (diagnostic != nullptr && diagnostic[0] != '\0') {
        proxyCheckDiagnostic = diagnostic;
    }
    if (previousDiagnostic == proxyCheckDiagnostic) {
        return;
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup pre_tcp_timeout_diagnostic phase=%s reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, proxyCheckDiagnostic.c_str(), reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

std::string ConnectionSocket::deriveMtProxyTerminalDiagnostic(int32_t reason, int32_t error) {
    if (!isCurrentMtProxyConnection() || reason == 0) {
        return proxyCheckDiagnostic;
    }
    // Diagnostics decided pre-I/O (before the socket connects) must survive the close path.
    // deriveMtProxyTerminalDiagnostic would otherwise re-derive them from the startup timeline as
    // "connection_not_started" (startupActive is true because the socket never connected), which is on
    // the local-scheduler-timeout skip list -> records neither an endpoint cooldown nor a reconnect
    // hold. handshake_profiles_exhausted can be decided by mtProxyProbeBeginOrJoin before a socket is
    // opened, so preserving it lets endpoint cooldown + reconnect backoff engage instead of a hot loop.
    if (proxyCheckDiagnostic == MtProxyPhase::SecretParseInvalidDomainControlChar
            || proxyCheckDiagnostic == MtProxyPhase::SecretParseInvalidDomain
            || proxyCheckDiagnostic == "dns_negative_cache_hit"
            || proxyCheckDiagnostic == "dns_blocked_zero_address"
            || proxyCheckDiagnostic == MtProxyPhase::HandshakeProfilesExhausted) {
        return proxyCheckDiagnostic;
    }
    bool startupActive = startupTimeline.hasLocalWait()
            || startupTimeline.dnsResolveAttemptStarted()
            || startupTimeline.tcpConnectAttemptStarted()
            || !mtproxySocketConnectedLogged;
    if (startupActive) {
        const char *timelineDiagnostic = startupTimeline.terminalDiagnostic(mtproxySocketConnectedLogged);
        if (!mtproxySocketConnectedLogged && startupTimeline.tcpConnectAttemptStarted()) {
            if (error == ECONNREFUSED) {
                return MtProxyPhase::TcpConnectionRefused;
            }
            if (error == ETIMEDOUT || reason == 2 || proxyCheckDiagnostic == MtProxyPhase::TcpConnectTimeout) {
                return MtProxyPhase::TcpConnectTimeout;
            }
        }
        classifyMtProxyPreTcpTimeoutDiagnostic("derive_terminal");
        return timelineDiagnostic;
    }
    return proxyCheckDiagnostic.empty() ? std::string("unknown_fail") : proxyCheckDiagnostic;
}

bool ConnectionSocket::mtProxyDiagnosticIsLocalSchedulerTimeout(const char *diagnostic) {
    if (diagnostic == nullptr) {
        return false;
    }
    return strcmp(diagnostic, "connection_not_started") == 0
           || strcmp(diagnostic, "admission_timeout") == 0
           || strcmp(diagnostic, "tcp_connect_gate_timeout") == 0
           || strcmp(diagnostic, "endpoint_cooldown_timeout") == 0
           || strcmp(diagnostic, "dns_coalesce_timeout") == 0
           || strcmp(diagnostic, "background_handshake_aborted") == 0;
}

void ConnectionSocket::setMtProxySocketConnectedLogged(bool logged, const char *reason) {
    if (mtproxySocketConnectedLogged == logged) {
        return;
    }
    mtproxySocketConnectedLogged = logged;
    if (logged) {
        startupTimeline.finishTcpConnect();
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport socket_connected_logged_state_change logged=%d reason=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, mtproxySocketConnectedLogged ? 1 : 0, reason != nullptr ? reason : "unknown", transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

bool ConnectionSocket::canStartHostResolve() {
    if (waitingForHostResolve.empty()) {
        logTransportInvariant("host_resolve_start", "no_pending_host");
        return false;
    }
    return checkTransportActionRequirements("host_resolve_start");
}

void ConnectionSocket::checkHostResolveCallback(const std::string &host) {
    if (waitingForHostResolve != host) {
        return;
    }
    if (!checkTransportActionRequirements("host_resolve_callback")) {
        logTransportInvariant("host_resolve_callback", "invalid_state");
        if (LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_transport host_resolve_callback_invariant host=%s transport_state=%s admission_active=%d admission_queued=%d waiting_resolve=%d", this, host.c_str(), transportStateName(currentTransportState), proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1);
        }
    }
}

void ConnectionSocket::setWaitingForHostResolve(const std::string &host, const char *reason) {
    if (waitingForHostResolve == host) {
        return;
    }
    waitingForHostResolve = host;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport host_resolve_state_change waiting=%d reason=%s waiting_resolve=%d host_len=%zu transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d proxy_state=%d tls_state=%d", this, waitingForHostResolve.empty() ? 0 : 1, reason != nullptr ? reason : "unknown", waitingForHostResolve.empty() ? 0 : 1, waitingForHostResolve.size(), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, (int) proxyAuthState, (int) tlsState);
    }
}

bool ConnectionSocket::canNotifyConnected(const char *action) {
    if (!checkTransportActionRequirements(action)) {
        return false;
    }
    if (onConnectedSent) {
        logTransportInvariant(action, "already_notified");
        return false;
    }
    return true;
}

void ConnectionSocket::setSocketCloseNotified(bool notified, const char *reason) {
    if (socketCloseNotified == notified) {
        return;
    }
    socketCloseNotified = notified;
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport socket_close_notify_state_change notified=%d reason=%s close_notified=%d transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, notified ? 1 : 0, reason != nullptr ? reason : "unknown", socketCloseNotified ? 1 : 0, transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

void ConnectionSocket::setConnectedNotified(bool sent, const char *reason) {
    if (onConnectedSent == sent) {
        return;
    }
    onConnectedSent = sent;
    if (NETWORK_DEBUG_LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport connected_notify_state_change sent=%d reason=%s connected_notified=%d transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, sent ? 1 : 0, reason != nullptr ? reason : "unknown", onConnectedSent ? 1 : 0, transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
    }
}

bool ConnectionSocket::canDeliverReceivedData(const char *action) {
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canSendWssFrame() {
    return checkTransportActionRequirements("sendWssFrame");
}

bool ConnectionSocket::canQueueOutboundBuffer(const char *action) {
    if (isClosingOrClosedForWrites()) {
        logTransportInvariant(action, "dead_for_writes");
        if (LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_transport write_suppressed_dead_connection action=%s phase=%s transport_state=%s close_notified=%d dead_for_writes=%d", this, action != nullptr ? action : "unknown", proxyCheckDiagnostic.c_str(), transportStateName(currentTransportState), socketCloseNotified ? 1 : 0, socketDeadForWrites ? 1 : 0);
        }
        return false;
    }
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canSendRawSocketBytes(const char *action) {
    return checkTransportActionRequirements(action);
}

bool ConnectionSocket::canReceiveRawSocketBytes() {
    return checkTransportActionRequirements("raw_socket_recv");
}

void ConnectionSocket::markConnectionDeadForWrites(const char *reason) {
    if (socketDeadForWrites) {
        return;
    }
    socketDeadForWrites = true;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_transport dead_for_writes reason=%s phase=%s transport_state=%s close_notified=%d", this, reason != nullptr ? reason : "unknown", proxyCheckDiagnostic.c_str(), transportStateName(currentTransportState), socketCloseNotified ? 1 : 0);
    }
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
    if (!canSendRawSocketBytes("raw_client_hello_send")) {
        return false;
    }
    while (pendingClientHello != nullptr && pendingClientHelloOffset < limit) {
        ssize_t sentLength = stateMachine.sendBytes(pendingClientHello->bytes + pendingClientHelloOffset, limit - pendingClientHelloOffset, 0);
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
    if (!canSendPendingClientHello()) {
        return false;
    }
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
    nextTlsFrameWriteTime = 0;
}

bool ConnectionSocket::scheduleMtProxyDataTimingIfNeeded() {
    int32_t timingMode = effectiveMtProxyTimingMode();
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyDataTimingWaitInput input;
    input.timingMode = timingMode;
    input.hasPendingTlsFrame = pendingTlsFrame != nullptr;
    input.nextWriteTime = nextTlsFrameWriteTime;
    input.now = now;
    MtProxyDataTimingWaitDecision waitDecision = mtProxyDataTimingWaitDecision(input);
    if (waitDecision.clearScheduledTime) {
        nextTlsFrameWriteTime = 0;
    }
    if (!waitDecision.shouldWait) {
        return false;
    }
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_data timing_delay mode=%d startup_cover=%d delay=%u", this, (int) timingMode, currentStartupCoverMode, waitDecision.delayMs);
    }
    scheduleProxyHandshakeAdmissionTimer(waitDecision.delayMs, MT_PROXY_HANDSHAKE_TIMER_TLS_FRAME, proxyHandshakeAdmissionIpv6);
    return true;
}

void ConnectionSocket::startMtProxyStartupCover() {
    MtProxyStartupCoverPolicy policy = mtProxyStartupCoverPolicy(currentSecretIsFakeTls, currentStartupCoverMode);
    if (!policy.enabled) {
        return;
    }
    startupCoverStartTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    startupCoverFrameCount = 0;
    startupCoverStartedLogged = true;
    startupCoverEndedLogged = false;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_data startup_cover_start mode=%d window_ms=%lld max_frames=%u", this, policy.mode, (long long) policy.windowMs, policy.maxFrames);
    }
}

bool ConnectionSocket::mtProxyStartupCoverActive() {
    MtProxyStartupCoverPolicy policy = mtProxyStartupCoverPolicy(currentSecretIsFakeTls, currentStartupCoverMode);
    if (!policy.enabled || startupCoverStartTime == 0) {
        return false;
    }
    int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    MtProxyStartupCoverState state;
    state.startTime = startupCoverStartTime;
    state.frameCount = startupCoverFrameCount;
    MtProxyStartupCoverEvaluation evaluation = mtProxyEvaluateStartupCover(policy, state, now);
    if (evaluation.shouldEnd) {
        if (!startupCoverEndedLogged && LOGS_ENABLED) {
            DEBUG_D("connection(%p) mtproxy_data startup_cover_end mode=%d elapsed=%lld frames=%u", this, policy.mode, (long long) evaluation.elapsedMs, startupCoverFrameCount);
        }
        startupCoverEndedLogged = true;
        startupCoverStartTime = 0;
        return false;
    }
    return evaluation.active;
}

int32_t ConnectionSocket::effectiveMtProxyRecordSizingMode() {
    return mtProxyEffectiveRecordSizingMode(currentRecordSizingMode, currentStartupCoverMode, mtProxyStartupCoverActive());
}

int32_t ConnectionSocket::effectiveMtProxyTimingMode() {
    return mtProxyEffectiveTimingMode(currentTimingMode, currentStartupCoverMode, mtProxyStartupCoverActive());
}

bool ConnectionSocket::buildPendingTlsFrame(NativeByteBuffer *buffer, uint32_t remaining) {
    if (pendingTlsFrame != nullptr || buffer == nullptr || remaining == 0) {
        return false;
    }
    MtProxyRecordSizingInput sizingInput;
    sizingInput.recordSizingMode = currentRecordSizingMode;
    sizingInput.startupCoverMode = currentStartupCoverMode;
    sizingInput.startupCoverActive = mtProxyStartupCoverActive();
    sizingInput.firstTlsFrameSent = mtproxyFirstTlsFrameSentLogged;
    sizingInput.remaining = remaining;
    sizingInput.randomBounded = secureRandomBounded;
    MtProxyRecordSizingDecision sizingDecision = nextMtProxyTlsRecordPayloadSize(sizingInput);
    if (sizingDecision.effectiveRecordSizingMode != MT_PROXY_RECORD_SIZING_OFF && LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_data record_sizing mode=%d startup_cover=%d cap=%u remaining=%u first_sent=%d", this, (int) sizingDecision.effectiveRecordSizingMode, currentStartupCoverMode, sizingDecision.payloadSize, remaining, mtproxyFirstTlsFrameSentLogged ? 1 : 0);
    }
    if (remaining > sizingDecision.payloadSize) {
        remaining = sizingDecision.payloadSize;
    }
    size_t headersSize = 0;
    if (tlsState == 1) {
        static std::string header1 = std::string("\x14\x03\x03\x00\x01\x01", 6);
        std::memcpy(tempBuffer->bytes, header1.data(), header1.size());
        headersSize += header1.size();
        setTlsState(2, "first_tls_frame_header");
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
    if (!canSendPendingTlsFrame()) {
        return false;
    }
    if (!canSendRawSocketBytes("raw_tls_frame_send")) {
        return false;
    }
    while (pendingTlsFrame != nullptr && pendingTlsFrameOffset < pendingTlsFrameSize) {
        ssize_t sentLength = stateMachine.sendBytes(pendingTlsFrame->bytes + pendingTlsFrameOffset, pendingTlsFrameSize - pendingTlsFrameOffset, 0);
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
            firstTransportPacketSent = true;
            mtproxyFirstTlsFrameSentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
            publishProxyConnectionStage("first_tls_app_sent");
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_tls_app_sent payload=%u frame=%u", this, pendingTlsPayloadSize, pendingTlsFrameSize);
        }
        outgoingByteStream->discard(pendingTlsPayloadSize);
        mtproxyTlsFrameCompletedCount++;
        bool startupCoverActive = mtProxyStartupCoverActive();
        if (LOGS_ENABLED && (mtproxyTlsFrameCompletedCount <= 8 || startupCoverActive)) {
            DEBUG_D("connection(%p) mtproxy_data tls_frame_complete index=%u payload=%u frame=%u record_sizing=%d timing=%d startup_cover=%d more_data=%d", this, mtproxyTlsFrameCompletedCount, pendingTlsPayloadSize, pendingTlsFrameSize, (int) effectiveMtProxyRecordSizingMode(), (int) effectiveMtProxyTimingMode(), currentStartupCoverMode, outgoingByteStream->hasData() ? 1 : 0);
        }
        if (startupCoverActive) {
            startupCoverFrameCount++;
            mtProxyStartupCoverActive();
        }
        clearPendingTlsFrame();
        MtProxyDataTimingInput timingInput;
        timingInput.timingMode = currentTimingMode;
        timingInput.startupCoverMode = currentStartupCoverMode;
        timingInput.startupCoverActive = mtProxyStartupCoverActive();
        timingInput.hasPendingTlsFrame = pendingTlsFrame != nullptr;
        timingInput.hasOutgoingData = outgoingByteStream->hasData();
        timingInput.randomBounded = secureRandomBounded;
        MtProxyDataTimingDecision timingDecision = mtProxyDataTimingDecision(timingInput);
        if (timingDecision.shouldDelay) {
            nextTlsFrameWriteTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis() + timingDecision.delayMs;
            if (LOGS_ENABLED) {
                DEBUG_D("connection(%p) mtproxy_data timing_next mode=%d startup_cover=%d delay=%u", this, (int) timingDecision.effectiveTimingMode, currentStartupCoverMode, timingDecision.delayMs);
            }
        }
        adjustWriteOp();
    }
    return true;
}

bool ConnectionSocket::resetTransportSocketForOpenConnection() {
    bool hasOpenResources = socketFd >= 0
            || epollRegistered
            || currentTransportState != TransportState::Idle
            || !waitingForHostResolve.empty()
            || adjustWriteOpAfterResolve
            || adjustWriteOpAfterPreTcpGate
            || startupTimeline.dnsResolveAttemptStarted()
            || startupTimeline.tcpConnectAttemptStarted()
            || startupTimeline.hasLocalWait()
            || proxyHandshakeAdmissionActive
            || proxyHandshakeAdmissionQueued
            || proxyHandshakeAdmissionQueuePublished
            || proxyHandshakeAdmissionReady
            || proxyEndpointTcpConnectActive
            || proxyEndpointTcpConnectReady
            || proxyEndpointTcpConnectGatePublished
            || proxyEndpointBackoffReady
            || proxyEndpointDnsCoalesceReady;
    if (hasOpenResources) {
        logTransportSnapshot("open_connection_reset", "openConnection_reset");
        if (currentTransportState != TransportState::Closing) {
            setTransportState(TransportState::Closing, "openConnection_reset");
        }
        if (epollRegistered) {
            if (socketFd >= 0 && canUnregisterEpollSocket()) {
                stateMachine.epollCtlDel(ConnectionsManager::getInstance(instanceNum).epolFd);
            }
            setEpollRegistered(false, "openConnection_reset_epoll_ctl_del");
        }
        if (socketFd >= 0) {
            if (canCloseNativeSocket()) {
                if (!stateMachine.closeNativeSocket("openConnection_reset_close_native_socket") && LOGS_ENABLED) {
                    DEBUG_E("connection(%p) unable to close stale socket during openConnection reset", this);
                }
            }
            setSocketFd(-1, "openConnection_reset_close_native_socket");
        }
    }
    setWaitingForHostResolve("", "openConnection_reset_cleanup");
    setAdjustWriteOpAfterResolve(false, "openConnection_reset_cleanup");
    setAdjustWriteOpAfterPreTcpGate(false, "openConnection_reset_cleanup");
    setMtProxyTcpConnectAttemptStarted(false, "openConnection_reset_cleanup");
    setMtProxyDnsResolveAttemptStarted(false, "openConnection_reset_cleanup");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "openConnection_reset_cleanup");
    setProxyHandshakeAdmissionState(0, 0, 0, 0, "openConnection_reset_cleanup");
    setProxyEndpointTcpConnectGateState(0, 0, 0, "openConnection_reset_cleanup");
    setProxyEndpointBackoffReady(false, "openConnection_reset_cleanup");
    setProxyEndpointDnsCoalesceReady(false, "openConnection_reset_cleanup");
    setTransportState(TransportState::Idle, "openConnection_reset_cleanup");
    bool resetClean = socketFd < 0
            && !epollRegistered
            && currentTransportState == TransportState::Idle
            && waitingForHostResolve.empty()
            && !adjustWriteOpAfterResolve
            && !adjustWriteOpAfterPreTcpGate
            && !startupTimeline.dnsResolveAttemptStarted()
            && !startupTimeline.tcpConnectAttemptStarted()
            && !startupTimeline.hasLocalWait()
            && !proxyHandshakeAdmissionActive
            && !proxyHandshakeAdmissionQueued
            && !proxyEndpointTcpConnectActive;
    if (!resetClean) {
        logTransportInvariant("openConnection", "reset_not_clean");
        logTransportSnapshot("open_connection_reset_failed", "openConnection_reset_cleanup");
    }
    return resetClean;
}

void ConnectionSocket::openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType, int32_t datacenterId, bool mediaConnection) {
    ConnectionsManager &manager = ConnectionsManager::getInstance(instanceNum);
    proxyActivationGeneration = manager.getProxyActivationGeneration();
    proxyActivationOrigin = manager.getProxyActivationOrigin();
    releaseMtProxyProbeLease();
    releaseMtProxyEndpointTcpConnect("openConnection_reset");
    cancelProxyHandshakeAdmission();
    if (!resetTransportSocketForOpenConnection()) {
        proxyCheckDiagnostic = "connection_not_started";
        if (LOGS_ENABLED) DEBUG_E("connection(%p) mtproxy_startup open_connection_reset_failed address=%s port=%u", this, address.c_str(), (unsigned int) port);
        return;
    }
    clearPendingClientHello();
    clearPendingTlsFrame();
    currentNetworkType = networkType;
    isIpv6 = ipv6;
    setSocketCloseNotified(false, "openConnection");
    proxyCloseDiagnosticSuppressed = false;
    socketDeadForWrites = false;
    setEpollRegistered(false, "openConnection");
    setTransportState(TransportState::Prepared, "openConnection");
    stateMachine.setTransportMode(TransportMode::None);
    currentAddress = address;
    currentPort = port;
    currentSocksUsername.clear();
    currentSocksPassword.clear();
    setWaitingForHostResolve("", "openConnection");
    setAdjustWriteOpAfterResolve(false, "openConnection");
    setAdjustWriteOpAfterPreTcpGate(false, "openConnection");
    setMtProxyTcpConnectAttemptStarted(false, "openConnection");
    setMtProxyDnsResolveAttemptStarted(false, "openConnection");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "openConnection");
    currentSecret = "";
    currentSecretDomain = "";
    currentOriginalSecretDomain = "";
    currentSanitizedSecretDomain = "";
    currentLowercaseSecretDomain = "";
    currentNoTrailingDotSecretDomain = "";
    currentPunycodeSecretDomain = "";
    currentClientHelloSni = "";
    currentSecretKind = "none";
    currentSecretIsFakeTls = false;
    currentAllowedSniVariants = 0;
    currentRecipeFamily = MtProxyAdaptivePolicy::CLIENT_HELLO_CHROME_MODERN_SOFT_FRAGMENT;
    currentRecipeSniVariant = MtProxyAdaptivePolicy::SNI_ORIGINAL;
    currentRecipeParserVariant = MtProxyAdaptivePolicy::PARSER_STANDARD_HMAC;
    currentRecipeClassicVariant = MtProxyAdaptivePolicy::CLASSIC_NONE;
    currentTransportWss = false;
    currentDatacenterId = datacenterId;
    currentMediaConnection = mediaConnection;
    currentWssTransport.reset();
    currentWssRoute = WssRouteConfig();
    currentProxyTlsProfile = normalizeMtProxyTlsProfile(MT_PROXY_TLS_PROFILE_ANDROID_CHROME);
    currentEffectiveProxyTlsProfile = currentProxyTlsProfile;
    currentClientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    currentServerHelloParserMode = MT_PROXY_SERVER_HELLO_PARSER_STANDARD;
    currentConnectionPatternMode = MT_PROXY_CONNECTION_PATTERN_OFF;
    currentRecordSizingMode = MT_PROXY_RECORD_SIZING_OFF;
    currentTimingMode = MT_PROXY_TIMING_OFF;
    currentStartupCoverMode = MT_PROXY_STARTUP_COVER_OFF;
    startupCoverStartTime = 0;
    startupCoverFrameCount = 0;
    startupCoverStartedLogged = false;
    startupCoverEndedLogged = false;
    nextTlsFrameWriteTime = 0;
    currentProxyTlsProfileKey = "";
    currentMtProxyEndpointKey = "";
    currentMtProxyRecipeCacheKey = "";
    currentMtProxyProbeKey = "";
    currentMtProxyNetworkEndpointKey = "";
    currentMtProxyDnsCacheKey = "";
    currentMtProxyAdmissionKey = "";
    proxyCheckDiagnostic = "connection_not_started";
    proxyHandshakeAdmissionKey = "";
    setProxyHandshakeAdmissionState(-1, 0, -1, -1, "openConnection");
    setProxyEndpointBackoffReady(false, "openConnection");
    setProxyEndpointTcpConnectGateState(0, 0, 0, "openConnection");
    setProxyEndpointDnsCoalesceReady(false, "openConnection");
    setTlsState(0, "openConnection");
    setMtProxySocketConnectedLogged(false, "openConnection");
    mtproxyFirstTlsFrameSentLogged = false;
    mtproxyFirstTlsDataReceivedLogged = false;
    mtproxyFirstPlainDataSentLogged = false;
    mtproxyFirstPlainDataReceivedLogged = false;
    firstTransportPacketSent = false;
    firstTransportPacketReceived = false;
    dataPathProven = false;
    mtproxyFirstTlsFrameSentTime = 0;
    mtproxyFirstPlainDataSentTime = 0;
    mtproxyFirstDataReceivedTime = 0;
    mtproxyTlsFrameCompletedCount = 0;
    ConnectionsManager::getInstance(instanceNum).attachConnection(this);

    memset(&socketAddress, 0, sizeof(sockaddr_in));
    memset(&socketAddress6, 0, sizeof(sockaddr_in6));

    std::string *proxyAddress = &overrideProxyAddress;
    std::string *proxySecret = &overrideProxySecret;
    uint16_t proxyPort = overrideProxyPort;
    MtProxyOptions proxyOptions = overrideMtProxyOptions;
    std::string wssFallbackProxyAddress;
    std::string wssFallbackProxyUsername;
    std::string wssFallbackProxyPassword;
    std::string wssFallbackProxySecret;
    uint16_t wssFallbackProxyPort = 1080;
    if (proxyAddress->empty()) {
        proxyAddress = &ConnectionsManager::getInstance(instanceNum).proxyAddress;
        proxyPort = ConnectionsManager::getInstance(instanceNum).proxyPort;
        proxySecret = &ConnectionsManager::getInstance(instanceNum).proxySecret;
        proxyOptions = ConnectionsManager::getInstance(instanceNum).proxyMtProxyOptions;
    }

    bool shouldUseWss = overrideProxyAddress.empty()
            && manager.wssEnabled
            && manager.wssTransportMode != WssTransport::WSS_TRANSPORT_OFF;
    WssRouteConfig selectedWssRoute;
    if (shouldUseWss) {
        if (manager.wssTransportMode == WssTransport::WSS_TRANSPORT_OFFICIAL) {
            selectedWssRoute = WssTransport::officialRouteFor(datacenterId, mediaConnection);
            if (selectedWssRoute.mode == WssTransport::WSS_TRANSPORT_OFF) {
                shouldUseWss = false;
                if (manager.wssSocksEnabled && !manager.wssSocksHost.empty()) {
                    wssFallbackProxyAddress = manager.wssSocksHost;
                    wssFallbackProxyPort = manager.wssSocksPort == 0 ? 1080 : manager.wssSocksPort;
                    wssFallbackProxyUsername = manager.wssSocksUsername;
                    wssFallbackProxyPassword = manager.wssSocksPassword;
                    proxyAddress = &wssFallbackProxyAddress;
                    proxyPort = wssFallbackProxyPort;
                    proxySecret = &wssFallbackProxySecret;
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) wss_startup dc%d has no stable official route, fallback_to_socks socks=%s:%u", this, datacenterId, wssFallbackProxyAddress.c_str(), (uint32_t) wssFallbackProxyPort);
                } else {
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) wss_startup dc%d has no stable official route, fallback to TCP", this, datacenterId);
                }
            }
        } else {
            selectedWssRoute = WssTransport::customRoute(
                    manager.wssTransportMode,
                    manager.wssGatewayMode,
                    manager.wssHost,
                    manager.wssPort,
                    manager.wssPath,
                    address,
                    port,
                    manager.wssSocksHost,
                    manager.wssSocksPort,
                    manager.wssSocksUsername,
                    manager.wssSocksPassword,
                    manager.wssSocksEnabled);
        }
        if (shouldUseWss && manager.wssSocksEnabled && !manager.wssSocksHost.empty()) {
            selectedWssRoute.upstreamSocksAddress = manager.wssSocksHost;
            selectedWssRoute.upstreamSocksPort = manager.wssSocksPort == 0 ? 1080 : manager.wssSocksPort;
            selectedWssRoute.upstreamSocksUsername = manager.wssSocksUsername;
            selectedWssRoute.upstreamSocksPassword = manager.wssSocksPassword;
            selectedWssRoute.upstreamSocksEnabled = true;
        }
    }

    if (shouldUseWss) {
        currentTransportWss = true;
        stateMachine.setTransportMode(TransportMode::Wss);
        currentSecretKind = "wss";
        setProxyAuthState(0, "wss_setup");
        currentWssRoute = selectedWssRoute;
        std::string wssConnectHost = (wssUsedRelayFallback && !currentWssRoute.relayHostFallback.empty())
                ? currentWssRoute.relayHostFallback
                : currentWssRoute.relayIp;
        uint16_t wssConnectPort = currentWssRoute.relayPort;
        if (currentWssRoute.upstreamSocksEnabled) {
            wssConnectHost = currentWssRoute.upstreamSocksAddress;
            wssConnectPort = currentWssRoute.upstreamSocksPort == 0 ? 1080 : currentWssRoute.upstreamSocksPort;
            if (LOGS_ENABLED) DEBUG_D("connection(%p) wss_startup connect_via_socks socks=%s:%u relay=%s:%u domain=%s", this, wssConnectHost.c_str(), (uint32_t) wssConnectPort, currentWssRoute.relayIp.c_str(), (uint32_t) currentWssRoute.relayPort, currentWssRoute.domain.c_str());
        }
        if (!canCreateSocket("create_wss_socket")) {
            closeSocket(1, -1);
            return;
        }
        int createdFd = stateMachine.createNativeSocket(AF_INET, SOCK_STREAM, 0);
        setSocketFd(createdFd, "create_wss_socket");
        if (socketFd < 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) can't create WSS socket", this);
            closeSocket(1, -1);
            return;
        }
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = htons(wssConnectPort);
        bool continueCheckAddress = false;
        if (inet_pton(AF_INET, wssConnectHost.c_str(), &socketAddress.sin_addr.s_addr) != 1) {
            continueCheckAddress = true;
        }
        if (continueCheckAddress) {
            if (inet_pton(AF_INET6, wssConnectHost.c_str(), &socketAddress6.sin6_addr.s6_addr) == 1) {
                if (stateMachine.closeNativeSocket("create_wss_ipv6_reopen")) {
                    setSocketFd(-1, "create_wss_ipv6_reopen");
                    if (!canCreateSocket("create_wss_ipv6_socket")) {
                        closeSocket(1, -1);
                        return;
                    }
                    int createdIpv6Fd = stateMachine.createNativeSocket(AF_INET6, SOCK_STREAM, 0);
                    setSocketFd(createdIpv6Fd, "create_wss_ipv6_socket");
                }
                if (socketFd < 0) {
                    closeSocket(1, -1);
                    return;
                }
                socketAddress6.sin6_family = AF_INET6;
                socketAddress6.sin6_port = htons(wssConnectPort);
                ipv6 = true;
                continueCheckAddress = false;
            }
        }
        if (continueCheckAddress) {
#ifdef USE_DELEGATE_HOST_RESOLVE
            setWaitingForHostResolve(wssConnectHost, "wss_host_resolve_start");
            if (!canStartHostResolve()) {
                closeSocket(1, -1);
                return;
            }
            setMtProxyDnsResolveAttemptStarted(true, "host_resolve_start");
            setTransportState(TransportState::WaitingGate, "host_resolve_start");
            ConnectionsManager::getInstance(instanceNum).delegate->getHostByName(wssConnectHost, instanceNum, this);
            return;
#else
            struct hostent *he;
            if ((he = gethostbyname(wssConnectHost.c_str())) == nullptr) {
                proxyCheckDiagnostic = "host_resolve_failed";
                if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve WSS host %s address", this, wssConnectHost.c_str());
                closeSocket(1, -1);
                return;
            }
            struct in_addr **addr_list = (struct in_addr **) he->h_addr_list;
            if (addr_list[0] != nullptr) {
                socketAddress.sin_addr.s_addr = addr_list[0]->s_addr;
                ipv6 = false;
            } else {
                proxyCheckDiagnostic = "host_resolve_failed";
                closeSocket(1, -1);
                return;
            }
#endif
        }
    } else if (!proxyAddress->empty()) {
        currentSecretKind = proxySecret->empty() ? "socks" : mtProxySecretKindName(*proxySecret);
        if (LOGS_ENABLED) DEBUG_D("connection(%p) connecting via proxy %s:%d secret[%d] secret_kind=%s", this, proxyAddress->c_str(), proxyPort, (int) proxySecret->size(), currentSecretKind);
        uint32_t tempBuffLength;
        if (proxySecret->empty()) {
            stateMachine.setTransportMode(TransportMode::Socks5);
            setProxyAuthState(1, "socks_proxy_setup");
            tempBuffLength = 1024;
            if (!wssFallbackProxyAddress.empty()) {
                currentAddress = address;
                currentPort = port;
                currentSocksUsername = wssFallbackProxyUsername;
                currentSocksPassword = wssFallbackProxyPassword;
                currentSecret = "";
                currentSecretDomain = "";
            } else if (!overrideProxyAddress.empty()) {
                currentSocksUsername = overrideProxyUser;
                currentSocksPassword = overrideProxyPassword;
            } else {
                currentSocksUsername = ConnectionsManager::getInstance(instanceNum).proxyUser;
                currentSocksPassword = ConnectionsManager::getInstance(instanceNum).proxyPassword;
            }
        } else if (proxySecret->size() > 17 && (*proxySecret)[0] == '\xee') {
            stateMachine.setTransportMode(TransportMode::FakeTlsMtProxy);
            setProxyAuthState(10, "faketls_proxy_setup");
            currentSecret = proxySecret->substr(1, 16);
            MtProxySecretDomainPlan domainPlan = buildMtProxySecretDomainPlan(proxySecret->substr(17));
            currentSecretDomain = domainPlan.canonicalDomain;
            currentOriginalSecretDomain = domainPlan.originalDomain;
            currentSanitizedSecretDomain = domainPlan.sanitizedDomain;
            currentLowercaseSecretDomain = domainPlan.lowercaseAsciiDomain;
            currentNoTrailingDotSecretDomain = domainPlan.noTrailingDotDomain;
            currentPunycodeSecretDomain = domainPlan.punycodeDomain;
            currentClientHelloSni = currentSecretDomain;
            currentAllowedSniVariants = domainPlan.allowedSniVariants;
            currentSecretIsFakeTls = true;
            currentMtProxyDnsCacheKey = MtProxyEndpointPolicy::dnsCacheKeyFor(*proxyAddress, proxyPort);
            currentMtProxyNetworkEndpointKey = MtProxyEndpointPolicy::networkEndpointKeyFor(*proxyAddress, proxyPort);
            currentMtProxyAdmissionKey = MtProxyEndpointPolicy::admissionKeyFor(*proxyAddress, proxyPort, currentSecretDomain);
            currentProxyTlsProfile = normalizeMtProxyTlsProfile(proxyOptions.tlsProfile);
            currentMtProxyEndpointKey = MtProxyEndpointPolicy::endpointKeyFor(*proxyAddress, proxyPort, currentSecretKind, currentSecretDomain);
            currentMtProxyRecipeCacheKey = mtProxyRecipeCacheKeyFor(*proxyAddress, proxyPort, currentSecret, currentSecretDomain);
            currentMtProxyProbeKey = currentMtProxyRecipeCacheKey;
            currentProxyTlsProfileKey = currentMtProxyRecipeCacheKey;
            if (domainPlan.terminalDiagnostic != nullptr) {
                if (strcmp(domainPlan.terminalDiagnostic, MtProxyPhase::SecretParseInvalidDomainControlChar) == 0) {
                    proxyCheckDiagnostic = MtProxyPhase::SecretParseInvalidDomainControlChar;
                } else {
                    proxyCheckDiagnostic = MtProxyPhase::SecretParseInvalidDomain;
                }
                if (LOGS_ENABLED) DEBUG_E("connection(%p) mtproxy_startup secret_domain_invalid phase=%s raw_len=%d sanitized=%s", this, proxyCheckDiagnostic.c_str(), (int) (proxySecret->size() - 17), currentSecretDomain.c_str());
                closeSocket(1, -1);
                return;
            }
            if (domainPlan.sanitized) {
                publishSanitizedSecretDomainIfNeeded(proxySecret->size() - 17);
            }
            currentEffectiveProxyTlsProfile = MtProxyAdaptivePolicy::resolveEffectiveTlsProfile(currentProxyTlsProfile, currentProxyTlsProfileKey);
            currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(proxyOptions.clientHelloFragmentation);
            currentConnectionPatternMode = normalizeMtProxyConnectionPatternMode(proxyOptions.connectionPatternMode);
            currentRecordSizingMode = normalizeMtProxyRecordSizingMode(proxyOptions.recordSizingMode);
            currentTimingMode = normalizeMtProxyTimingMode(proxyOptions.timingMode);
            currentStartupCoverMode = normalizeMtProxyStartupCoverMode(proxyOptions.startupCoverMode);
            if (mtProxyProbeBeginOrJoin(ipv6)) {
                return;
            }
            applyMtProxyPhaseAdaptiveRecipe();
            proxyHandshakeAdmissionKey = currentMtProxyAdmissionKey;
            tempBuffLength = 65 * 1024;
        } else {
            stateMachine.setTransportMode(TransportMode::PlainMtProxy);
            setProxyAuthState(0, "plain_proxy_setup");
            std::string plainSecretHash = "secret_hash=" + mtProxySecretHashForRecipeKey(*proxySecret);
            currentMtProxyDnsCacheKey = MtProxyEndpointPolicy::dnsCacheKeyFor(*proxyAddress, proxyPort);
            currentMtProxyNetworkEndpointKey = MtProxyEndpointPolicy::networkEndpointKeyFor(*proxyAddress, proxyPort);
            currentMtProxyEndpointKey = MtProxyEndpointPolicy::endpointKeyFor(*proxyAddress, proxyPort, currentSecretKind, plainSecretHash);
            currentMtProxyRecipeCacheKey = "";
            currentMtProxyProbeKey = mtProxyRecipeCacheKeyFor(*proxyAddress, proxyPort, *proxySecret, "");
            currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(proxyOptions.clientHelloFragmentation);
            currentConnectionPatternMode = normalizeMtProxyConnectionPatternMode(proxyOptions.connectionPatternMode);
            currentRecordSizingMode = normalizeMtProxyRecordSizingMode(proxyOptions.recordSizingMode);
            currentTimingMode = normalizeMtProxyTimingMode(proxyOptions.timingMode);
            currentStartupCoverMode = normalizeMtProxyStartupCoverMode(proxyOptions.startupCoverMode);
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
        if (!canCreateSocket("create_proxy_socket")) {
            closeSocket(1, -1);
            return;
        }
        int createdFd = stateMachine.createNativeSocket(AF_INET, SOCK_STREAM, 0);
        setSocketFd(createdFd, "create_proxy_socket");
        if (socketFd < 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) can't create proxy socket", this);
            closeSocket(1, -1);
            return;
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
                if (MtProxyEndpointPolicy::extractSslipIpv4Address(*proxyAddress, &socketAddress.sin_addr, &sslipAddress)) {
                    ipv6 = false;
                    continueCheckAddress = false;
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup resolved_sslip host=%s address=%s", this, proxyAddress->c_str(), sslipAddress.c_str());
                }
            }
            if (continueCheckAddress) {
                bool blockedZeroAddress = false;
                if (mtProxyEndpointUseCachedHostAddress(*proxyAddress, &ipv6, &blockedZeroAddress)) {
                    continueCheckAddress = false;
                }
                if (blockedZeroAddress) {
                    return;
                }
            }
            if (continueCheckAddress) {
#ifdef USE_DELEGATE_HOST_RESOLVE
                setWaitingForHostResolve(*proxyAddress, "host_resolve_pending");
                if (isCurrentMtProxyConnection() && scheduleMtProxyEndpointCircuitBreakerIfNeeded(ipv6)) {
                    return;
                }
                if (proxyAuthState >= 10 && scheduleProxyHandshakeAdmissionIfNeeded(ipv6, MT_PROXY_HANDSHAKE_TIMER_HOST_RESOLVE)) {
                    return;
                }
                if (isCurrentMtProxyConnection() && scheduleMtProxyDnsCoalesceIfNeeded(ipv6)) {
                    return;
                }
                requestPendingHostResolve();
                return;
#else
                struct hostent *he;
                if ((he = gethostbyname(proxyAddress->c_str())) == nullptr) {
                    proxyCheckDiagnostic = "host_resolve_failed";
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address", this, proxyAddress->c_str());
                    closeSocket(1, -1);
                    return;
                }
                struct in_addr **addr_list = (struct in_addr **) he->h_addr_list;
                if (addr_list[0] != nullptr) {
                    socketAddress.sin_addr.s_addr = addr_list[0]->s_addr;
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) resolved host %s address %x", this, proxyAddress->c_str(), addr_list[0]->s_addr);
                    ipv6 = false;
                    char resolvedIp[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, addr_list[0], resolvedIp, sizeof(resolvedIp)) != nullptr) {
                        mtProxyEndpointStoreResolvedAddress(*proxyAddress, resolvedIp);
                    }
                } else {
                    proxyCheckDiagnostic = "host_resolve_failed";
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address", this, proxyAddress->c_str());
                    closeSocket(1, -1);
                    return;
                }
#endif
            }
        }
    } else {
        stateMachine.setTransportMode(secret.empty() ? TransportMode::Direct : TransportMode::PlainMtProxy);
        setProxyAuthState(0, "direct_setup");
        uint32_t tempBuffLength;
        currentSecretKind = mtProxySecretKindName(secret);
        if (secret.size() > 17 && secret[0] == '\xee') {
            stateMachine.setTransportMode(TransportMode::FakeTlsMtProxy);
            setProxyAuthState(10, "faketls_direct_setup");
            currentSecret = secret.substr(1, 16);
            MtProxySecretDomainPlan domainPlan = buildMtProxySecretDomainPlan(secret.substr(17));
            currentSecretDomain = domainPlan.canonicalDomain;
            currentOriginalSecretDomain = domainPlan.originalDomain;
            currentSanitizedSecretDomain = domainPlan.sanitizedDomain;
            currentLowercaseSecretDomain = domainPlan.lowercaseAsciiDomain;
            currentNoTrailingDotSecretDomain = domainPlan.noTrailingDotDomain;
            currentPunycodeSecretDomain = domainPlan.punycodeDomain;
            currentClientHelloSni = currentSecretDomain;
            currentAllowedSniVariants = domainPlan.allowedSniVariants;
            currentSecretIsFakeTls = true;
            currentMtProxyNetworkEndpointKey = MtProxyEndpointPolicy::networkEndpointKeyFor(address, port);
            currentMtProxyAdmissionKey = MtProxyEndpointPolicy::admissionKeyFor(address, port, currentSecretDomain);
            const MtProxyOptions managerOptions = ConnectionsManager::getInstance(instanceNum).proxyMtProxyOptions;
            currentProxyTlsProfile = normalizeMtProxyTlsProfile(managerOptions.tlsProfile);
            currentMtProxyEndpointKey = MtProxyEndpointPolicy::endpointKeyFor(address, port, currentSecretKind, currentSecretDomain);
            currentMtProxyRecipeCacheKey = mtProxyRecipeCacheKeyFor(address, port, currentSecret, currentSecretDomain);
            currentMtProxyProbeKey = currentMtProxyRecipeCacheKey;
            currentProxyTlsProfileKey = currentMtProxyRecipeCacheKey;
            if (domainPlan.terminalDiagnostic != nullptr) {
                if (strcmp(domainPlan.terminalDiagnostic, MtProxyPhase::SecretParseInvalidDomainControlChar) == 0) {
                    proxyCheckDiagnostic = MtProxyPhase::SecretParseInvalidDomainControlChar;
                } else {
                    proxyCheckDiagnostic = MtProxyPhase::SecretParseInvalidDomain;
                }
                if (LOGS_ENABLED) DEBUG_E("connection(%p) mtproxy_startup secret_domain_invalid phase=%s raw_len=%d sanitized=%s", this, proxyCheckDiagnostic.c_str(), (int) (secret.size() - 17), currentSecretDomain.c_str());
                closeSocket(1, -1);
                return;
            }
            if (domainPlan.sanitized) {
                publishSanitizedSecretDomainIfNeeded(secret.size() - 17);
            }
            currentEffectiveProxyTlsProfile = MtProxyAdaptivePolicy::resolveEffectiveTlsProfile(currentProxyTlsProfile, currentProxyTlsProfileKey);
            currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(managerOptions.clientHelloFragmentation);
            currentConnectionPatternMode = normalizeMtProxyConnectionPatternMode(managerOptions.connectionPatternMode);
            currentRecordSizingMode = normalizeMtProxyRecordSizingMode(managerOptions.recordSizingMode);
            currentTimingMode = normalizeMtProxyTimingMode(managerOptions.timingMode);
            currentStartupCoverMode = normalizeMtProxyStartupCoverMode(managerOptions.startupCoverMode);
            tempBuffLength = 65 * 1024;
        } else {
            setProxyAuthState(0, "plain_direct_setup");
            if (!secret.empty()) {
                std::string plainSecretHash = "secret_hash=" + mtProxySecretHashForRecipeKey(secret);
                currentMtProxyNetworkEndpointKey = MtProxyEndpointPolicy::networkEndpointKeyFor(address, port);
                currentMtProxyEndpointKey = MtProxyEndpointPolicy::endpointKeyFor(address, port, currentSecretKind, plainSecretHash);
                currentMtProxyRecipeCacheKey = "";
                currentMtProxyProbeKey = mtProxyRecipeCacheKeyFor(address, port, secret, "");
                const MtProxyOptions managerOptions = ConnectionsManager::getInstance(instanceNum).proxyMtProxyOptions;
                currentClientHelloFragmentation = normalizeMtProxyClientHelloFragmentation(managerOptions.clientHelloFragmentation);
                currentConnectionPatternMode = normalizeMtProxyConnectionPatternMode(managerOptions.connectionPatternMode);
                currentRecordSizingMode = normalizeMtProxyRecordSizingMode(managerOptions.recordSizingMode);
                currentTimingMode = normalizeMtProxyTimingMode(managerOptions.timingMode);
                currentStartupCoverMode = normalizeMtProxyStartupCoverMode(managerOptions.startupCoverMode);
            }
            tempBuffLength = 0;
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
        if (currentSecretIsFakeTls) {
            if (mtProxyProbeBeginOrJoin(ipv6)) {
                return;
            }
            applyMtProxyPhaseAdaptiveRecipe();
            proxyHandshakeAdmissionKey = currentMtProxyAdmissionKey;
        }
        if (tempBuffLength > 0) {
            if (tempBuffer == nullptr || tempBuffer->length < tempBuffLength) {
                if (tempBuffer != nullptr) {
                    delete tempBuffer;
                }
                tempBuffer = new ByteArray(tempBuffLength);
            }
        }
        if (!canCreateSocket("create_direct_socket")) {
            closeSocket(1, -1);
            return;
        }
        int createdFd = stateMachine.createNativeSocket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        setSocketFd(createdFd, "create_direct_socket");
        if (socketFd < 0) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) can't create socket", this);
            closeSocket(1, -1);
            return;
        }
    }

    publishProxyConnectionStage("connect_start");
    if (LOGS_ENABLED) {
        if (currentTransportWss) {
            DEBUG_D("connection(%p) wss_startup connect_start mode=%d gateway=%d relay=%s:%u domain=%s path=%s target=%s:%u upstream_socks=%s:%u upstream_enabled=%d", this, (int) currentWssRoute.mode, (int) currentWssRoute.gatewayMode, currentWssRoute.relayIp.c_str(), (unsigned int) currentWssRoute.relayPort, currentWssRoute.domain.c_str(), currentWssRoute.path.c_str(), currentAddress.c_str(), (unsigned int) currentPort, currentWssRoute.upstreamSocksAddress.c_str(), (unsigned int) currentWssRoute.upstreamSocksPort, currentWssRoute.upstreamSocksEnabled ? 1 : 0);
        } else {
            DEBUG_D("connection(%p) mtproxy_startup connect_start proxy_state=%d secret_kind=%s is_faketls=%d domain_len=%d profile=%s effective_profile=%s clienthello_fragment=%d server_hello_parser=%s connection_pattern=%s record_sizing=%d timing=%d startup_cover=%d address=%s port=%u", this, (int) proxyAuthState, currentSecretKind, currentSecretIsFakeTls ? 1 : 0, (int) currentSecretDomain.size(), mtProxyTlsProfileName(currentProxyTlsProfile), mtProxyTlsProfileName(currentEffectiveProxyTlsProfile), currentClientHelloFragmentation, mtProxyServerHelloParserName(currentServerHelloParserMode), mtProxyConnectionPatternModeName(currentConnectionPatternMode), currentRecordSizingMode, currentTimingMode, currentStartupCoverMode, currentAddress.c_str(), (unsigned int) currentPort);
        }
    }
    openConnectionInternal(ipv6);
}

void ConnectionSocket::openConnectionInternal(bool ipv6) {
    if (isCurrentMtProxyConnection() && scheduleMtProxyEndpointCircuitBreakerIfNeeded(ipv6)) {
        return;
    }
    if (proxyAuthState >= 10) {
        if (scheduleProxyHandshakeAdmissionIfNeeded(ipv6, MT_PROXY_HANDSHAKE_TIMER_ADMISSION)) {
            return;
        }
    }
    int epolFd = ConnectionsManager::getInstance(instanceNum).epolFd;
    if (!canConfigureOpenSocket()) {
        closeSocket(1, -1);
        return;
    }
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

    if (isCurrentMtProxyConnection() && scheduleMtProxyEndpointTcpConnectGateIfNeeded(ipv6)) {
        return;
    }

    finishMtProxyPreTcpWait("socket_connect_start");
    publishProxyConnectionStage("socket_connect_start");
    setTransportState(TransportState::TcpConnecting, "socket_connect_start");
    setMtProxyTcpConnectAttemptStarted(true, "socket_connect_start");
    proxyCheckDiagnostic = MtProxyPhase::TcpNotConnected;
    if (LOGS_ENABLED) DEBUG_D("connection(%p) %s socket_connect_start ipv6=%d state=%d", this, currentTransportWss ? "wss_startup" : "mtproxy_startup", ipv6 ? 1 : 0, (int) proxyAuthState);
    if (!canStartTcpConnect()) {
        closeSocket(1, -1);
        return;
    }
    if (!stateMachine.connectNativeSocket((ipv6 ? (sockaddr *) &socketAddress6 : (sockaddr *) &socketAddress), (socklen_t) (ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in)))) {
        closeSocket(1, -1);
    } else {
        eventMask.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
        eventMask.data.ptr = eventObject;
        if (!canRegisterEpollSocket()) {
            closeSocket(1, -1);
            return;
        }
        if (!stateMachine.epollCtlAdd(epolFd)) {
            if (LOGS_ENABLED) DEBUG_E("connection(%p) epoll_ctl, adding socket failed", this);
            closeSocket(1, -1);
        } else {
            setEpollRegistered(true, "epoll_ctl_add");
            setTransportState(TransportState::EpollRegistered, "epoll_ctl_add");
        }
    }
    if (epollRegistered && (adjustWriteOpAfterResolve || adjustWriteOpAfterPreTcpGate)) {
        if (adjustWriteOpAfterResolve) {
            setAdjustWriteOpAfterResolve(false, "epoll_ctl_add");
        }
        if (adjustWriteOpAfterPreTcpGate) {
            setAdjustWriteOpAfterPreTcpGate(false, "epoll_ctl_add");
        }
        adjustWriteOp();
    }
}

int32_t ConnectionSocket::checkSocketError(int32_t *error) {
    if (!canCheckSocketError()) {
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

bool ConnectionSocket::isCurrentTransportWss() {
    return currentTransportWss && currentWssRoute.mode != WssTransport::WSS_TRANSPORT_OFF;
}

bool ConnectionSocket::isCurrentMtProxyConnection() {
    return currentSecretKind != nullptr
           && strcmp(currentSecretKind, "none") != 0
           && strcmp(currentSecretKind, "socks") != 0
           && strcmp(currentSecretKind, "wss") != 0;
}

bool ConnectionSocket::dispatchWssPayloads(std::vector<std::vector<uint8_t>> &payloads) {
    for (auto &payload : payloads) {
        if (payload.empty()) {
            continue;
        }
        if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
            ConnectionsManager::getInstance(instanceNum).delegate->onBytesReceived((int32_t) payload.size(), currentNetworkType, instanceNum);
        }
        NativeByteBuffer *wssBuffer = BuffersStorage::getInstance().getFreeBuffer((uint32_t) payload.size());
        wssBuffer->writeBytes(payload.data(), (uint32_t) payload.size());
        wssBuffer->rewind();
        if (!canDeliverReceivedData("wss_payload_recv")) {
            wssBuffer->reuse();
            closeSocket(1, -1);
            return false;
        }
        onReceivedData(wssBuffer);
        if (isDisconnected()) {
            return false;
        }
    }
    return true;
}

void ConnectionSocket::publishSanitizedSecretDomainIfNeeded(size_t rawDomainLength) {
    if (!isCurrentMtProxyConnection() || currentMtProxyEndpointKey.empty()) {
        return;
    }
    if (!MtProxyEndpointPolicy::recordSecretDomainSanitized(currentMtProxyEndpointKey)) {
        return;
    }
    proxyCheckDiagnostic = "secret_domain_sanitized";
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup secret_domain_sanitized raw_len=%d sanitized=%s", this, (int) rawDomainLength, currentSecretDomain.c_str());
    }
    publishProxyConnectionStage("secret_domain_sanitized");
}

void ConnectionSocket::publishProxyConnectionStage(const char *diagnostic) {
    if (!isCurrentMtProxyConnection() || !overrideProxyAddress.empty() || diagnostic == nullptr) {
        return;
    }
    std::string endpointKey = currentMtProxyEndpointKey;
    if (endpointKey.empty()) {
        endpointKey = currentMtProxyNetworkEndpointKey;
    }
    if (endpointKey.empty() && !currentAddress.empty() && currentPort != 0) {
        endpointKey = MtProxyEndpointPolicy::networkEndpointKeyFor(currentAddress, currentPort);
    }
    if (endpointKey.empty()) {
        return;
    }
    ConnectionsManager &manager = ConnectionsManager::getInstance(instanceNum);
    if (manager.delegate != nullptr) {
        std::string origin = proxyConnectionStageOrigin();
        if (origin == "active_socket" && !proxyActivationOrigin.empty()) {
            origin = proxyActivationOrigin;
        }
        manager.delegate->onProxyConnectionStageChanged(instanceNum, diagnostic, endpointKey, currentMtProxyProbeKey, origin, (int32_t) proxyActivationGeneration);
    }
}

void ConnectionSocket::publishMtProxySocketObservation(const MtProxySocketObservation &observation) {
    MtProxySocketObservation enriched = observation;
    if (enriched.endpointKey.empty()) {
        enriched.endpointKey = currentMtProxyEndpointKey;
    }
    if (enriched.probeKey.empty()) {
        enriched.probeKey = currentMtProxyProbeKey;
    }
    if (enriched.networkEndpointKey.empty()) {
        enriched.networkEndpointKey = currentMtProxyNetworkEndpointKey;
    }
    MtProxySocketPublisherCallbacks callbacks;
    callbacks.publishVisibleStage = [this](const MtProxySocketObservation &publishedObservation) {
        publishProxyConnectionStage(publishedObservation.phase);
    };
    callbacks.recordEndpointFailure = [this](const MtProxySocketObservation &publishedObservation) {
        recordMtProxyEndpointFailure(publishedObservation.phase, publishedObservation.reason);
    };
    mtProxyPublishSocketObservation(enriched, callbacks);
}

std::string ConnectionSocket::proxyConnectionStageOrigin() {
    return "active_socket";
}

bool ConnectionSocket::matchesMtProxyEndpointKey(const std::string &endpointKey) {
    if (endpointKey.empty() || !isCurrentMtProxyConnection()) {
        return false;
    }
    if (endpointKey == currentMtProxyEndpointKey || endpointKey == currentMtProxyNetworkEndpointKey) {
        return true;
    }
    if (!currentMtProxyEndpointKey.empty()
            && currentMtProxyEndpointKey.size() > endpointKey.size()
            && currentMtProxyEndpointKey.compare(0, endpointKey.size(), endpointKey) == 0
            && currentMtProxyEndpointKey[endpointKey.size()] == ':') {
        return true;
    }
    return !currentMtProxyNetworkEndpointKey.empty()
            && endpointKey.size() > currentMtProxyNetworkEndpointKey.size()
            && endpointKey.compare(0, currentMtProxyNetworkEndpointKey.size(), currentMtProxyNetworkEndpointKey) == 0
            && endpointKey[currentMtProxyNetworkEndpointKey.size()] == ':';
}

bool ConnectionSocket::matchesMtProxyProbeKey(const std::string &probeKey) {
    return !probeKey.empty()
            && isCurrentMtProxyConnection()
            && !currentMtProxyProbeKey.empty()
            && probeKey == currentMtProxyProbeKey;
}

void ConnectionSocket::cancelMtProxyEndpointAttempt(const char *reason) {
    if (!isCurrentMtProxyConnection()) {
        return;
    }
    const char *safeReason = reason != nullptr && reason[0] != '\0' ? reason : "unknown";
    proxyCheckDiagnostic = "ignored_cancelled_generation";
    proxyCloseDiagnosticSuppressed = true;
    suppressNextProxyCloseDiagnostic = true;
    publishProxyConnectionStage("ignored_cancelled_generation");
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup endpoint_attempt_cancelled endpoint=%s probe=%s network_key=%s reason=%s", this, currentMtProxyEndpointKey.c_str(), currentMtProxyProbeKey.c_str(), currentMtProxyNetworkEndpointKey.c_str(), safeReason);
    }
    releaseMtProxyEndpointTcpConnect("endpoint_attempt_cancelled");
    releaseProxyHandshakeAdmission(false, "endpoint_attempt_cancelled");
    cancelProxyHandshakeAdmission();
    closeSocket(1, ECANCELED);
}

void ConnectionSocket::markMtProxyFirstPlainDataSent(uint32_t bytes) {
    if (!isCurrentMtProxyConnection() || currentSecretIsFakeTls || bytes == 0 || mtproxyFirstPlainDataSentLogged) {
        return;
    }
    mtproxyFirstPlainDataSentLogged = true;
    firstTransportPacketSent = true;
    mtproxyFirstPlainDataSentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    proxyCheckDiagnostic = "mtproxy_packet_sent_no_response";
    publishProxyConnectionStage("first_mtproxy_packet_sent");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_mtproxy_packet_sent bytes=%u secret_kind=%s", this, bytes, currentSecretKind);
}

void ConnectionSocket::markMtProxyFirstPlainDataReceived(uint32_t bytes) {
    if (!isCurrentMtProxyConnection() || currentSecretIsFakeTls || bytes == 0 || mtproxyFirstPlainDataReceivedLogged) {
        return;
    }
    mtproxyFirstPlainDataReceivedLogged = true;
    firstTransportPacketReceived = true;
    dataPathProven = true;
    mtproxyFirstPlainDataSentTime = 0;
    mtproxyFirstDataReceivedTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    proxyCheckDiagnostic = "dropped_after_appdata";
    MtProxySocketObservation observation;
    observation.phase = MtProxyPhase::FirstMtproxyPacketRecv;
    observation.reason = MtProxyPhase::FirstMtproxyPacketRecv;
    publishMtProxySocketObservation(observation);
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_mtproxy_packet_recv bytes=%u secret_kind=%s", this, bytes, currentSecretKind);
    recordMtProxyEndpointDataPathSuccess("first_mtproxy_packet_recv");
}

void ConnectionSocket::rotateMtProxyTlsProfileOnFailureIfNeeded(int32_t reason, int32_t error) {
    if (!currentSecretIsFakeTls || currentProxyTlsProfile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE || currentProxyTlsProfileKey.empty()) {
        return;
    }
    if (reason == 0 && error == 0) {
        return;
    }
    MtProxyAdaptivePolicy::RotateResult rotation = MtProxyAdaptivePolicy::rotateTlsProfileOnFailureIfNeeded(currentProxyTlsProfileKey, proxyCheckDiagnostic, currentEffectiveProxyTlsProfile);
    if (!rotation.rotated) {
        return;
    }
    if (LOGS_ENABLED) DEBUG_D("mtproxy_startup profile_rotate key=%s phase=%s previous=%s next=%s failures=%u", currentProxyTlsProfileKey.c_str(), proxyCheckDiagnostic.c_str(), mtProxyTlsProfileName(rotation.previousProfile), mtProxyTlsProfileName(rotation.nextProfile), rotation.failures);
}

void ConnectionSocket::logMtProxyTlsAfterClientHello(size_t responseBytes) {
    if (!LOGS_ENABLED || tempBuffer == nullptr || responseBytes == 0) {
        return;
    }
    const uint8_t *data = tempBuffer->bytes;
    std::string hex = mtProxyHexPreview(data, responseBytes);
    MtProxyServerFlightRecordInfo recordInfo = mtProxyServerFlightReadRecordInfo(data, responseBytes);
    DEBUG_D("connection(%p) mtproxy_startup mtproxy_tls_after_client_hello bytes=%zu hex=%s record_type=%d tls_version=0x%02x%02x record_len=%d alert_level=%d alert_description=%d", this, responseBytes, hex.c_str(), recordInfo.recordType, recordInfo.tlsMajor < 0 ? 0 : recordInfo.tlsMajor, recordInfo.tlsMinor < 0 ? 0 : recordInfo.tlsMinor, recordInfo.recordLength, recordInfo.alertLevel, recordInfo.alertDescription);
}

const char *ConnectionSocket::classifyMtProxyPostClientHelloResponse(size_t responseBytes) {
    if (tempBuffer == nullptr || responseBytes == 0) {
        return "true_client_hello_timeout";
    }
    const uint8_t *data = tempBuffer->bytes;
    if (mtProxyServerFlightLooksLikeTlsAlert(data, responseBytes)) {
        return "tls_alert_after_client_hello";
    }
    if (responseBytes < 5 || mtProxyServerFlightHandshakeRecordNeedsMoreBytes(data, responseBytes)) {
        return "short_tls_response_after_client_hello";
    }
    return "unrecognized_response_after_client_hello";
}

void ConnectionSocket::closeMtProxyPostClientHelloResponse(const char *diagnostic, const char *reason, int32_t error) {
    if (diagnostic == nullptr || diagnostic[0] == '\0') {
        diagnostic = "unrecognized_response_after_client_hello";
    }
    proxyCheckDiagnostic = diagnostic;
    if (LOGS_ENABLED) {
        DEBUG_D("connection(%p) mtproxy_startup post_client_hello_response_failed phase=%s reason=%s bytes=%zu", this, proxyCheckDiagnostic.c_str(), reason != nullptr ? reason : "unknown", bytesRead);
    }
    closeSocket(1, error);
}

void ConnectionSocket::closeSocket(int32_t reason, int32_t error) {
    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
    if (socketCloseNotified) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup close_ignored_already_closed reason=%s error=%s phase=%s transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d", this, mtProxyDisconnectReasonName(reason), mtProxySocketErrorName(error), proxyCheckDiagnostic.c_str(), transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState);
        return;
    }
    markConnectionDeadForWrites("closeSocket");
    logTransportSnapshot("close_start", "closeSocket");
    checkCloseSocketAction("closeSocket");
    setTransportState(TransportState::Closing, "closeSocket");
    setSocketCloseNotified(true, "closeSocket");
    bool forcedSuppressProxyCloseDiagnostic = suppressNextProxyCloseDiagnostic;
    suppressNextProxyCloseDiagnostic = false;
    proxyCloseDiagnosticSuppressed = forcedSuppressProxyCloseDiagnostic;
    if (reason != 0
            && isCurrentMtProxyConnection()
            && proxyCheckDiagnostic == "dropped_after_appdata"
            && mtproxyFirstDataReceivedTime > 0
            && lastEventTime - mtproxyFirstDataReceivedTime <= MT_PROXY_EARLY_APPDATA_DROP_MS) {
        proxyCheckDiagnostic = "dropped_early_after_appdata";
    }
    std::string terminalDiagnostic = deriveMtProxyTerminalDiagnostic(reason, error);
    if (!forcedSuppressProxyCloseDiagnostic && reason != 0 && isCurrentMtProxyConnection()) {
        proxyCheckDiagnostic = terminalDiagnostic;
    }
    bool suppressProxyCloseDiagnostic = false;
    if (forcedSuppressProxyCloseDiagnostic) {
        suppressProxyCloseDiagnostic = true;
    }
    bool shadowedSocketFailure = false;
    int64_t shadowedSocketFailureHoldMs = 0;
    if (!forcedSuppressProxyCloseDiagnostic && reason != 0 && isCurrentMtProxyConnection()) {
        if (terminalDiagnostic == MtProxyPhase::PostHandshakeNoAppdata
                || terminalDiagnostic == "mtproxy_packet_sent_no_response") {
            MtProxyEndpointPolicy::MtProxyEndpointContext context;
            context.endpointKey = currentMtProxyEndpointKey;
            context.recipeCacheKey = currentMtProxyRecipeCacheKey;
            context.networkEndpointKey = "";
            context.fakeTls = currentSecretIsFakeTls;
            int64_t now = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
            shadowedSocketFailureHoldMs = MtProxyEndpointPolicy::shadowFailureByFreshDataPathSuccess(context, terminalDiagnostic, now);
            if (shadowedSocketFailureHoldMs > 0) {
                suppressProxyCloseDiagnostic = true;
                shadowedSocketFailure = true;
            }
        }
        if (proxyCheckDiagnostic == MtProxyPhase::PostHandshakeNoAppdata
                && !mtproxyFirstTlsFrameSentLogged
                && !mtproxyFirstPlainDataSentLogged) {
            suppressProxyCloseDiagnostic = true;
        } else if (proxyCheckDiagnostic == "dropped_after_appdata"
                && (mtproxyFirstTlsDataReceivedLogged || mtproxyFirstPlainDataReceivedLogged)) {
            suppressProxyCloseDiagnostic = true;
        }
    }
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_disconnect reason=%d reason_text=%s error=%d error_text=%s secret_kind=%s is_faketls=%d is_wss=%d transport_state=%s epoll_registered=%d admission_active=%d admission_queued=%d tcp_gate_active=%d waiting_resolve=%d proxy_state=%d tls_state=%d bytes_read=%zu pending_hello=%u/%u pending=%u/%u first_tls_sent=%d first_tls_recv=%d first_plain_sent=%d first_plain_recv=%d tls_frames_completed=%u", this, reason, mtProxyDisconnectReasonName(reason), error, mtProxySocketErrorName(error), currentSecretKind, currentSecretIsFakeTls ? 1 : 0, currentTransportWss ? 1 : 0, transportStateName(currentTransportState), epollRegistered ? 1 : 0, proxyHandshakeAdmissionActive ? 1 : 0, proxyHandshakeAdmissionQueued ? 1 : 0, proxyEndpointTcpConnectActive ? 1 : 0, waitingForHostResolve.empty() ? 0 : 1, (int) proxyAuthState, (int) tlsState, bytesRead, pendingClientHelloOffset, pendingClientHelloSize, pendingTlsFrameOffset, pendingTlsFrameSize, mtproxyFirstTlsFrameSentLogged ? 1 : 0, mtproxyFirstTlsDataReceivedLogged ? 1 : 0, mtproxyFirstPlainDataSentLogged ? 1 : 0, mtproxyFirstPlainDataReceivedLogged ? 1 : 0, mtproxyTlsFrameCompletedCount);
    if (suppressProxyCloseDiagnostic) {
        proxyCloseDiagnosticSuppressed = true;
        if (shadowedSocketFailure) {
            publishProxyConnectionStage("shadowed_socket_failure");
            const char *heldBy = currentSecretIsFakeTls ? "first_tls_app_recv" : "first_mtproxy_packet_recv";
            if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup shadowed_socket_failure phase=%s held_by=%s hold_ms=%ld endpoint=%s network_key=%s", this, proxyCheckDiagnostic.c_str(), heldBy, (long) shadowedSocketFailureHoldMs, currentMtProxyEndpointKey.c_str(), currentMtProxyNetworkEndpointKey.c_str());
        }
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup close_diagnostic_suppressed phase=%s reason=%s first_tls_sent=%d first_tls_recv=%d first_plain_sent=%d first_plain_recv=%d", this, proxyCheckDiagnostic.c_str(), mtProxyDisconnectReasonName(reason), mtproxyFirstTlsFrameSentLogged ? 1 : 0, mtproxyFirstTlsDataReceivedLogged ? 1 : 0, mtproxyFirstPlainDataSentLogged ? 1 : 0, mtproxyFirstPlainDataReceivedLogged ? 1 : 0);
    } else {
        rotateMtProxyTlsProfileOnFailureIfNeeded(reason, error);
    }
    releaseMtProxyEndpointTcpConnect("closeSocket");
    if (!suppressProxyCloseDiagnostic && reason != 0 && isCurrentMtProxyConnection() && !terminalDiagnostic.empty()) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup close_diagnostic phase=%s", this, terminalDiagnostic.c_str());
        if (mtProxySocketObservationIsHighRiskPhase(terminalDiagnostic.c_str())) {
            MtProxySocketObservation observation;
            observation.phase = terminalDiagnostic.c_str();
            observation.reason = "closeSocket";
            observation.recordEndpointFailure = true;
            publishMtProxySocketObservation(observation);
        } else {
            publishProxyConnectionStage(terminalDiagnostic.c_str());
            recordMtProxyEndpointFailure(terminalDiagnostic.c_str(), "closeSocket");
        }
    }
    releaseMtProxyProbeLease();
    releaseProxyHandshakeAdmission(false, "closeSocket");
    cancelProxyHandshakeAdmission();
    ConnectionsManager::getInstance(instanceNum).detachConnection(this);
    if (socketFd >= 0) {
        if (epollRegistered) {
            if (canUnregisterEpollSocket()) {
                stateMachine.epollCtlDel(ConnectionsManager::getInstance(instanceNum).epolFd);
            }
            setEpollRegistered(false, "epoll_ctl_del");
        }
        if (canCloseNativeSocket()) {
            if (!stateMachine.closeNativeSocket("close_native_socket")) {
                if (LOGS_ENABLED) DEBUG_E("connection(%p) unable to close socket", this);
            }
        }
        setSocketFd(-1, "close_native_socket");
    }
    setWaitingForHostResolve("", "closeSocket_cleanup");
    setMtProxyTcpConnectAttemptStarted(false, "closeSocket_cleanup");
    setMtProxyDnsResolveAttemptStarted(false, "closeSocket_cleanup");
    setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "closeSocket_cleanup");
    setAdjustWriteOpAfterResolve(false, "closeSocket_cleanup");
    currentTransportWss = false;
    currentWssTransport.reset();
    currentWssRoute = WssRouteConfig();
    currentSocksUsername.clear();
    currentSocksPassword.clear();
    setProxyAuthState(0, "closeSocket_cleanup");
    setTlsState(0, "closeSocket_cleanup");
    setConnectedNotified(false, "closeSocket_cleanup");
    setMtProxySocketConnectedLogged(false, "closeSocket_cleanup");
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
    checkCloseSocketAction("closeSocket_cleanup");
    setTransportState(TransportState::Idle, "closeSocket_cleanup");
    onDisconnected(reason, error);
}

void ConnectionSocket::onEvent(uint32_t events) {
    if (!canProcessEpollEvent()) {
        return;
    }
    if (isCurrentTransportWss()) {
        if (events & (EPOLLIN | EPOLLOUT)) {
            int32_t error;
            if (checkSocketError(&error) != 0) {
                closeSocket(1, error);
                return;
            }
            if (currentWssTransport == nullptr) {
                currentWssTransport.reset(new WssTransport());
                if (!currentWssTransport->connect(socketFd, currentWssRoute)) {
                    if (LOGS_ENABLED) DEBUG_E("connection(%p) wss_startup init failed", this);
                    closeSocket(1, -1);
                    return;
                }
                proxyCheckDiagnostic = "wss_tls_handshake";
            }
            std::vector<std::vector<uint8_t>> payloads;
            std::string diagnostic;
            bool ok = true;
            if (events & EPOLLOUT) {
                ok = currentWssTransport->onWritable(payloads, &diagnostic);
            }
            if (ok && (events & EPOLLIN)) {
                ok = currentWssTransport->onReadable(payloads, &diagnostic);
            }
            if (!ok) {
                if (LOGS_ENABLED) DEBUG_E("connection(%p) wss_startup failed diagnostic=%s", this, diagnostic.c_str());
                closeSocket(1, -1);
                return;
            }
            if (!dispatchWssPayloads(payloads)) {
                return;
            }
            if (currentWssTransport != nullptr && currentWssTransport->isReady()) {
                if (!onConnectedSent) {
                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                    proxyCheckDiagnostic = MtProxyPhase::PostHandshakeNoAppdata;
                    setTransportState(TransportState::MtprotoReady, "wss_ready");
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) wss_startup on_connected mode=%d", this, currentWssRoute.mode);
                    if (!canNotifyConnected("wss_ready")) {
                        return;
                    }
                    onConnected();
                    setConnectedNotified(true, "wss_ready");
                }
                NativeByteBuffer *buffer = ConnectionsManager::getInstance(instanceNum).networkBuffer;
                buffer->clear();
                outgoingByteStream->get(buffer);
                buffer->flip();
                uint32_t remaining = buffer->remaining();
                if (remaining) {
                    if (!canSendWssFrame()) {
                        return;
                    }
                    if (!currentWssTransport->sendFrame(buffer->bytes(), remaining)) {
                        closeSocket(1, -1);
                        return;
                    }
                    if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
                        ConnectionsManager::getInstance(instanceNum).delegate->onBytesSent((int32_t) remaining, currentNetworkType, instanceNum);
                    }
                    outgoingByteStream->discard(remaining);
                    payloads.clear();
                    if (!currentWssTransport->onWritable(payloads, &diagnostic)) {
                        if (LOGS_ENABLED) DEBUG_E("connection(%p) wss_startup write failed diagnostic=%s", this, diagnostic.c_str());
                        closeSocket(1, -1);
                        return;
                    }
                    if (!dispatchWssPayloads(payloads)) {
                        return;
                    }
                }
            }
            adjustWriteOp();
        }
        if (events & EPOLLHUP) {
            if (LOGS_ENABLED) DEBUG_E("wss socket event has EPOLLHUP");
            closeSocket(1, -1);
            return;
        } else if (events & EPOLLRDHUP) {
            if (LOGS_ENABLED) DEBUG_E("wss socket event has EPOLLRDHUP");
            closeSocket(1, -1);
            return;
        }
        if (events & EPOLLERR) {
            int32_t error = -1;
            checkSocketError(&error);
            if (LOGS_ENABLED) DEBUG_E("connection(%p) wss epoll error code=%d", this, error);
            // Relay connect failed before the WSS path was up: alternate the
            // relay host (IP <-> domain) so the next reconnect tries the other
            // one. Reconnect reuses this Connection object, so the flag sticks.
            if (!currentWssRoute.relayHostFallback.empty()
                    && currentWssRoute.relayHostFallback != currentWssRoute.relayIp
                    && (currentWssTransport == nullptr || !currentWssTransport->isReady())) {
                wssUsedRelayFallback = !wssUsedRelayFallback;
                if (LOGS_ENABLED) DEBUG_D("connection(%p) wss_startup relay_alternate use_fallback=%d", this, wssUsedRelayFallback ? 1 : 0);
            }
            closeSocket(1, error);
            return;
        }
        return;
    }
    if (events & EPOLLIN) {
        int32_t error;
        if (checkSocketError(&error) != 0) {
            closeSocket(1, error);
            return;
        } else {
            if (!canReceiveRawSocketBytes()) {
                closeSocket(1, -1);
                return;
            }
            ssize_t readCount;
            NativeByteBuffer *buffer = ConnectionsManager::getInstance(instanceNum).networkBuffer;
            while (true) {
                buffer->rewind();
                readCount = stateMachine.recvBytes(buffer->bytes(), READ_BUFFER_SIZE, 0);
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
                        bool firstPostClientHelloRead = bytesRead == 0;
                        size_t newBytesRead = bytesRead + readCount;
                        if (newBytesRead > MT_PROXY_SERVER_FLIGHT_MAX_BYTES) {
                            proxyCheckDiagnostic = "unrecognized_response_after_client_hello";
                            closeMtProxyPostClientHelloResponse(proxyCheckDiagnostic.c_str(), "server_hello_too_much_data", -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS client hello too much data", this);
                            return;
                        }
                        std::memcpy(tempBuffer->bytes + bytesRead, buffer->bytes(), (size_t) readCount);
                        if (firstPostClientHelloRead) {
                            logMtProxyTlsAfterClientHello(newBytesRead);
                        }
                        if (mtProxyServerFlightLooksLikeTlsAlert(tempBuffer->bytes, newBytesRead)
                                && normalizeMtProxyServerHelloParserOption(currentServerHelloParserMode) != MT_PROXY_SERVER_HELLO_PARSER_TLS_ALERT_EXACT_DESC) {
                            bytesRead = newBytesRead;
                            closeMtProxyPostClientHelloResponse("tls_alert_after_client_hello", "tls_alert_record", -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS alert after ClientHello", this);
                            return;
                        }
                        if (newBytesRead < 5) {
                            bytesRead = newBytesRead;
                            return;
                        }

                        MtProxyServerFlightParseResult parseResult = mtProxyParseServerHelloFlight(currentSecret, tempBuffer->bytes + MT_PROXY_SERVER_FLIGHT_MAX_BYTES, tempBuffer->bytes, newBytesRead, currentServerHelloParserMode);
                        if (parseResult.invalid) {
                            tlsHashMismatch = true;
                            bytesRead = newBytesRead;
                            closeMtProxyPostClientHelloResponse(std::strcmp(parseResult.reason, "tls_alert_exact_desc") == 0 ? "tls_alert_after_client_hello" : "unrecognized_response_after_client_hello", parseResult.reason, -1);
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) TLS server hello parse invalid parser=%s reason=%s candidate=%zu", this, mtProxyServerHelloParserName(currentServerHelloParserMode), parseResult.reason, parseResult.candidateBytes);
                            return;
                        }
                        if (parseResult.waitMore) {
                            if (LOGS_ENABLED && std::strcmp(parseResult.reason, "server_hello_tail_data_wait") == 0) {
                                DEBUG_D("connection(%p) TLS server hello wait for tail data parser=%s reason=%s bytes=%zu candidate=%zu", this, mtProxyServerHelloParserName(currentServerHelloParserMode), parseResult.reason, newBytesRead, parseResult.candidateBytes);
                            } else if (LOGS_ENABLED) {
                                DEBUG_D("connection(%p) TLS server hello wait parser=%s reason=%s bytes=%zu candidate=%zu", this, mtProxyServerHelloParserName(currentServerHelloParserMode), parseResult.reason, newBytesRead, parseResult.candidateBytes);
                            }
                            bytesRead = newBytesRead;
                            return;
                        }
                        if (!parseResult.matched) {
                            proxyCheckDiagnostic = MtProxyPhase::ServerHelloHmacMismatch;
                            serverHelloHmacMismatchObserved = true;
                            if (serverHelloHmacMismatchTime == 0) {
                                serverHelloHmacMismatchTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                                scheduleProxyHandshakeAdmissionTimer((uint32_t) MT_PROXY_SERVER_HELLO_HMAC_WAIT_MS, MT_PROXY_HANDSHAKE_TIMER_SERVER_HELLO, proxyHandshakeAdmissionIpv6);
                            }
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) TLS server hello hmac wait parser=%s bytes=%zu candidate=%zu", this, mtProxyServerHelloParserName(currentServerHelloParserMode), newBytesRead, parseResult.candidateBytes);
                            bytesRead = newBytesRead;
                            return;
                        }
                        serverHelloHmacMismatchObserved = false;
                        serverHelloHmacMismatchTime = 0;
                        publishProxyConnectionStage("server_hello_hmac_ok");
                        recordMtProxyEndpointHandshakeOk("server_hello_hmac_ok");
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup server_hello_hmac_ok parser=%s bytes=%zu flight=%zu extra=%zu", this, mtProxyServerHelloParserName(currentServerHelloParserMode), parseResult.matchedBytes, parseResult.appFlightBytes, newBytesRead - parseResult.matchedBytes);
                        releaseProxyHandshakeAdmission(true, "server_hello_hmac_ok");
                        proxyCheckDiagnostic = MtProxyPhase::PostHandshakeNoAppdata;
                        setTlsState(1, "server_hello_hmac_ok");
                        startMtProxyStartupCover();
                        setTransportState(TransportState::MtprotoReady, "server_hello_hmac_ok");
                        setProxyAuthState(0, "server_hello_hmac_ok");
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
                                setProxyAuthState(3, "socks_auth_required");
                            } else if (auth_method == 0x00) {
                                setProxyAuthState(5, "socks_no_auth");
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
                                setProxyAuthState(5, "socks_auth_ok");
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
                                setProxyAuthState(0, "socks_connected");
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
                                                firstTransportPacketReceived = true;
                                                dataPathProven = true;
                                                mtproxyFirstTlsFrameSentTime = 0;
                                                mtproxyFirstDataReceivedTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                                                proxyCheckDiagnostic = "dropped_after_appdata";
                                                MtProxySocketObservation observation;
                                                observation.phase = MtProxyPhase::FirstTlsAppRecv;
                                                observation.reason = MtProxyPhase::FirstTlsAppRecv;
                                                publishMtProxySocketObservation(observation);
                                                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_tls_app_recv payload=%d", this, tlsBuffer->limit());
                                                recordMtProxyEndpointDataPathSuccess("first_tls_app_recv");
                                            }
                                            if (!canDeliverReceivedData("first_tls_app_recv")) {
                                                closeSocket(1, -1);
                                                return;
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
                            markMtProxyFirstPlainDataReceived((uint32_t) readCount);
                            if (!canDeliverReceivedData("first_mtproxy_packet_recv")) {
                                closeSocket(1, -1);
                                return;
                            }
                            onReceivedData(buffer);
                        }
                    }
                } else if (readCount == 0) {
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup recv_eof proxy_state=%d tls_state=%d", this, (int) proxyAuthState, (int) tlsState);
                    if (proxyAuthState == 11 && proxyHandshakeClientHelloSentTime != 0 && bytesRead == 0) {
                        proxyCheckDiagnostic = "server_closed_after_client_hello";
                    } else if (proxyAuthState == 11 && proxyHandshakeClientHelloSentTime != 0 && bytesRead > 0) {
                        logMtProxyTlsAfterClientHello(bytesRead);
                        proxyCheckDiagnostic = classifyMtProxyPostClientHelloResponse(bytesRead);
                    }
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
            if (!mtproxySocketConnectedLogged && isCurrentMtProxyConnection()) {
                setMtProxySocketConnectedLogged(true, "socket_connected");
                proxyCheckDiagnostic = "tcp_connected_no_pong";
                publishProxyConnectionStage("socket_connected");
                mtProxyProbeHeartbeat();
                releaseMtProxyEndpointTcpConnect("socket_connected");
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup socket_connected state=%d tls=%d secret_kind=%s", this, (int) proxyAuthState, (int) tlsState, currentSecretKind);
            }
            if (proxyAuthState != 0) {
                if (proxyAuthState >= 10) {
                    if (proxyAuthState == 10) {
                        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                        tlsHashMismatch = false;
                        serverHelloHmacMismatchObserved = false;
                        serverHelloHmacMismatchTime = 0;
                        setProxyAuthState(11, "client_hello_prepare");
                        setTransportState(TransportState::FaketlsHandshake, "client_hello_prepare");
                        const char *profileName = mtProxyTlsProfileName(currentEffectiveProxyTlsProfile);
                        TlsHello hello = selectMtProxyTlsHello(currentEffectiveProxyTlsProfile);
                        hello.setDomain(currentClientHelloSni);
                        uint32_t size = hello.writeToBuffer(tempBuffer->bytes);
                        if (!validateServerCompatibleHello(tempBuffer->bytes, size, currentClientHelloSni, profileName)) {
                            closeSocket(1, -1);
                            return;
                        }
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup profile selected=%s id=%d mode=%s server_hello_parser=%s sni_variant=%s client_hello_sni=%s hello=%u", this, profileName, (int) normalizeMtProxyTlsProfile(currentEffectiveProxyTlsProfile), mtProxyTlsProfileName(currentProxyTlsProfile), mtProxyServerHelloParserName(currentServerHelloParserMode), MtProxyAdaptivePolicy::sniVariantName(currentRecipeSniVariant), currentClientHelloSni.empty() ? "none" : currentClientHelloSni.c_str(), size);
                        uint32_t outLength;
                        HMAC(EVP_sha256(), currentSecret.data(), currentSecret.size(), tempBuffer->bytes, size, tempBuffer->bytes + MT_PROXY_SERVER_FLIGHT_MAX_BYTES, &outLength);

                        int32_t currentTime = ConnectionsManager::getInstance(instanceNum).getCurrentTime();
                        int32_t old = ((int32_t *) (tempBuffer->bytes + MT_PROXY_SERVER_FLIGHT_MAX_BYTES + 28))[0];
                        ((int32_t *) (tempBuffer->bytes + MT_PROXY_SERVER_FLIGHT_MAX_BYTES + 28))[0] = old ^ currentTime;

                        memcpy(tempBuffer->bytes + 11, tempBuffer->bytes + MT_PROXY_SERVER_FLIGHT_MAX_BYTES, 32);
                        logClientHelloFingerprint(this, profileName, tempBuffer->bytes, size);
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
                        proxyCheckDiagnostic = MtProxyPhase::FaketlsServerHelloWaitTimeout;
                        publishProxyConnectionStage("client_hello_sent");
                        mtProxyProbeHeartbeat();
                        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup client_hello_sent bytes=%u expected=%u domain_len=%d sni_variant=%s", this, size, size, (int) currentClientHelloSni.size(), MtProxyAdaptivePolicy::sniVariantName(currentRecipeSniVariant));
                        markProxyHandshakeClientHelloSent();
                        adjustWriteOp();
                    }
                } else {
                    if (proxyAuthState == 1) {
                        if (!canSendSocksHandshakeFrame("socks_method_select", 1)) {
                            return;
                        }
                        if (!canSendRawSocketBytes("raw_socks_method_send")) {
                            return;
                        }
                        lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                        tempBuffer->bytes[0] = 0x05;
                        tempBuffer->bytes[1] = 0x02;
                        tempBuffer->bytes[2] = 0x00;
                        tempBuffer->bytes[3] = 0x02;
                        if (stateMachine.sendBytes(tempBuffer->bytes, 4, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        setProxyAuthState(2, "socks_method_sent");
                        adjustWriteOp();
                    } else if (proxyAuthState == 3) {
                        if (!canSendSocksHandshakeFrame("socks_auth", 3)) {
                            return;
                        }
                        if (!canSendRawSocketBytes("raw_socks_auth_send")) {
                            return;
                        }
                        tempBuffer->bytes[0] = 0x01;
                        uint8_t len1 = (uint8_t) currentSocksUsername.length();
                        uint8_t len2 = (uint8_t) currentSocksPassword.length();
                        tempBuffer->bytes[1] = len1;
                        memcpy(tempBuffer->bytes + 2, currentSocksUsername.c_str(), len1);
                        tempBuffer->bytes[2 + len1] = len2;
                        memcpy(tempBuffer->bytes + 3 + len1, currentSocksPassword.c_str(), len2);
                        if (stateMachine.sendBytes(tempBuffer->bytes, 3 + len1 + len2, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        setProxyAuthState(4, "socks_auth_sent");
                        adjustWriteOp();
                    } else if (proxyAuthState == 5) {
                        if (!canSendSocksHandshakeFrame("socks_connect", 5)) {
                            return;
                        }
                        if (!canSendRawSocketBytes("raw_socks_connect_send")) {
                            return;
                        }
                        tempBuffer->bytes[0] = 0x05;
                        tempBuffer->bytes[1] = 0x01;
                        tempBuffer->bytes[2] = 0x00;
                        tempBuffer->bytes[3] = (uint8_t) (isIpv6 ? 0x04 : 0x01);
                        uint16_t networkPort = ntohs(currentPort);
                        inet_pton(isIpv6 ? AF_INET6 : AF_INET, currentAddress.c_str(), tempBuffer->bytes + 4);
                        memcpy(tempBuffer->bytes + 4 + (isIpv6 ? 16 : 4), &networkPort, sizeof(uint16_t));
                        if (stateMachine.sendBytes(tempBuffer->bytes, 4 + (isIpv6 ? 16 : 4) + 2, 0) < 0) {
                            if (LOGS_ENABLED) DEBUG_E("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        }
                        setProxyAuthState(6, "socks_connect_sent");
                        adjustWriteOp();
                    }
                }
            } else {
                if (!onConnectedSent) {
                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
                    setTransportState(TransportState::MtprotoReady, "on_connected");
                    publishProxyConnectionStage("on_connected");
                    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup on_connected tls=%d", this, (int) tlsState);
                    if (!canNotifyConnected("on_connected")) {
                        return;
                    }
                    onConnected();
                    setConnectedNotified(true, "on_connected");
                }
                if (tlsState != 0 && pendingTlsFrame != nullptr) {
                    if (!sendPendingTlsFrame()) {
                        return;
                    }
                    if (pendingTlsFrame != nullptr) {
                        return;
                    }
                }
                if (tlsState != 0 && scheduleMtProxyDataTimingIfNeeded()) {
                    return;
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
                        if (!canSendPlainMtProtoPayload()) {
                            return;
                        }
                        if (!canSendRawSocketBytes("raw_plain_mtproto_send")) {
                            return;
                        }
                        if ((sentLength = stateMachine.sendBytes(buffer->bytes(), remaining, 0)) < 0) {
                            if (LOGS_ENABLED) DEBUG_D("connection(%p) send failed", this);
                            closeSocket(1, -1);
                            return;
                        } else {
                            if (ConnectionsManager::getInstance(instanceNum).delegate != nullptr) {
                                ConnectionsManager::getInstance(instanceNum).delegate->onBytesSent((int32_t) sentLength, currentNetworkType, instanceNum);
                            }
                            markMtProxyFirstPlainDataSent((uint32_t) sentLength);
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
        int32_t error = -1;
        checkSocketError(&error);
        if (LOGS_ENABLED) DEBUG_E("connection(%p) epoll error code=%d", this, error);
        closeSocket(1, error);
        return;
    }
}

void ConnectionSocket::writeBuffer(uint8_t *data, uint32_t size) {
    if (!canQueueOutboundBuffer("writeBufferRaw")) {
        return;
    }
    NativeByteBuffer *buffer = BuffersStorage::getInstance().getFreeBuffer(size);
    buffer->writeBytes(data, size);
    outgoingByteStream->append(buffer);
    queueAdjustWriteOpAfterOutboundAppend("writeBufferRaw");
}

void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer) {
    if (!canQueueOutboundBuffer("writeBuffer")) {
        if (buffer != nullptr) {
            buffer->reuse();
        }
        return;
    }
    outgoingByteStream->append(buffer);
    queueAdjustWriteOpAfterOutboundAppend("writeBuffer");
}

void ConnectionSocket::queueAdjustWriteOpAfterOutboundAppend(const char *reason) {
    if (!waitingForHostResolve.empty()) {
        setAdjustWriteOpAfterResolve(true, reason);
        return;
    }
    if (!epollRegistered || currentTransportState == TransportState::Prepared || currentTransportState == TransportState::WaitingGate || currentTransportState == TransportState::TcpConnecting) {
        setAdjustWriteOpAfterPreTcpGate(true, reason);
        return;
    }
    adjustWriteOp();
}

void ConnectionSocket::adjustWriteOp() {
    if (!waitingForHostResolve.empty()) {
        setAdjustWriteOpAfterResolve(true, "adjustWriteOp_waiting_resolve");
        return;
    }
    if (!canModifyEpollWriteInterest("adjustWriteOp")) {
        return;
    }
    eventMask.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
    bool hasPendingClientHello = pendingClientHello != nullptr && pendingClientHelloOffset < pendingClientHelloSize;
    bool hasPendingTlsFrame = pendingTlsFrame != nullptr && pendingTlsFrameOffset < pendingTlsFrameSize;
    bool hasPendingWssWrite = currentTransportWss && currentWssTransport != nullptr && currentWssTransport->wantsWrite();
    if ((proxyAuthState == 0 && (hasPendingTlsFrame || hasPendingWssWrite || outgoingByteStream->hasData() || !onConnectedSent)) || proxyAuthState == 1 || proxyAuthState == 3 || proxyAuthState == 5 || proxyAuthState == 10 || (proxyAuthState == 11 && hasPendingClientHello)) {
        eventMask.events |= EPOLLOUT;
    }
    eventMask.data.ptr = eventObject;
    if (!stateMachine.epollCtlMod(ConnectionsManager::getInstance(instanceNum).epolFd)) {
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

int32_t ConnectionSocket::getCurrentNetworkType() const {
    return currentNetworkType;
}

bool ConnectionSocket::checkTimeout(int64_t now) {
    if (isCurrentMtProxyConnection()
        && currentSecretIsFakeTls
        && mtproxyFirstTlsFrameSentLogged
        && !mtproxyFirstTlsDataReceivedLogged
        && mtproxyFirstTlsFrameSentTime > 0
        && proxyCheckDiagnostic == MtProxyPhase::PostHandshakeNoAppdata
        && now - mtproxyFirstTlsFrameSentTime > MT_PROXY_TLS_APPDATA_NO_RESPONSE_TIMEOUT_MS) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup mtproxy_tls_appdata_no_response_timeout elapsed=%lld", this, (long long) (now - mtproxyFirstTlsFrameSentTime));
        MtProxySocketObservation observation;
        observation.phase = MtProxyPhase::PostHandshakeNoAppdata;
        observation.reason = "mtproxy_tls_appdata_no_response_timeout";
        publishMtProxySocketObservation(observation);
        closeSocket(2, 0);
        return true;
    }
    if (isCurrentMtProxyConnection()
        && !currentSecretIsFakeTls
        && mtproxyFirstPlainDataSentLogged
        && !mtproxyFirstPlainDataReceivedLogged
        && mtproxyFirstPlainDataSentTime > 0
        && proxyCheckDiagnostic == "mtproxy_packet_sent_no_response"
        && now - mtproxyFirstPlainDataSentTime > MT_PROXY_PLAIN_NO_RESPONSE_TIMEOUT_MS) {
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup mtproxy_packet_no_response_timeout elapsed=%lld", this, (long long) (now - mtproxyFirstPlainDataSentTime));
        publishProxyConnectionStage(proxyCheckDiagnostic.c_str());
        closeSocket(2, 0);
        return true;
    }
    if (isCurrentMtProxyConnection()) {
        MtProxyStartupTimeoutDecision startupDecision = startupTimeline.timeoutDecision(now, mtproxySocketConnectedLogged);
        if (startupDecision.active && !startupDecision.expired) {
            return false;
        }
        if (startupDecision.expired) {
            if (!onConnectedSent || hasPendingRequests()) {
                proxyCheckDiagnostic = startupDecision.diagnostic != nullptr ? startupDecision.diagnostic : "connection_not_started";
                if (LOGS_ENABLED) {
                    if (strcmp(proxyCheckDiagnostic.c_str(), MtProxyPhase::TcpConnectTimeout) == 0) {
                        DEBUG_D("connection(%p) mtproxy_startup tcp_connect_timeout elapsed_ms=%lld deadline_ms=%lld start_ms=%lld", this, (long long) startupDecision.elapsedMs, (long long) startupDecision.deadlineMs, (long long) startupDecision.startMs);
                    } else {
                        DEBUG_D("connection(%p) mtproxy_startup pre_tcp_timeout diagnostic=%s event=%s phase=%s elapsed_ms=%lld deadline_ms=%lld start_ms=%lld", this, proxyCheckDiagnostic.c_str(), startupDecision.event != nullptr ? startupDecision.event : "unknown", MtProxyStartupTimeline::phaseName(startupDecision.phase), (long long) startupDecision.elapsedMs, (long long) startupDecision.deadlineMs, (long long) startupDecision.startMs);
                    }
                }
                closeSocket(2, 0);
                return true;
            }
            lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();
            if (LOGS_ENABLED) DEBUG_D("connection(%p) reset last event time, no requests", this);
            return false;
        }
    }
    if (timeout != 0 && (now - lastEventTime) > (int64_t) timeout * 1000) {
        if (!onConnectedSent || hasPendingRequests()) {
            classifyMtProxyPreTcpTimeoutDiagnostic("checkTimeout");
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

void ConnectionSocket::setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, const MtProxyOptions &options) {
    overrideProxyAddress = address;
    overrideProxyPort = port;
    overrideProxyUser = username;
    overrideProxyPassword = password;
    overrideProxySecret = secret;
    overrideMtProxyOptions = normalizeMtProxyOptions(options);
}

void ConnectionSocket::requestPendingHostResolve() {
#ifdef USE_DELEGATE_HOST_RESOLVE
    if (waitingForHostResolve.empty()) {
        return;
    }
    if (!canStartHostResolve()) {
        closeSocket(1, -1);
        return;
    }
    ConnectionsManager &manager = ConnectionsManager::getInstance(instanceNum);
    if (manager.delegate == nullptr) {
        bool cachedIpv6 = false;
        bool blockedZeroAddress = false;
        if (mtProxyEndpointUseCachedHostAddress(waitingForHostResolve, &cachedIpv6, &blockedZeroAddress)) {
            setWaitingForHostResolve("", "host_resolve_cached_address");
            openConnectionInternal(cachedIpv6);
            return;
        }
        if (blockedZeroAddress) {
            return;
        }
        proxyCheckDiagnostic = "connection_not_started";
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup host_resolve_not_started host=%s reason=no_delegate", this, waitingForHostResolve.c_str());
        closeSocket(1, -1);
        return;
    }
    std::string host = waitingForHostResolve;
    if (manager.delegate->isHostResolveNegativeCached(host, instanceNum)) {
        setWaitingForHostResolve("", "dns_negative_cache_hit");
        setMtProxyDnsResolveAttemptStarted(false, "dns_negative_cache_hit");
        setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "dns_negative_cache_hit");
        proxyCheckDiagnostic = "dns_negative_cache_hit";
        publishProxyConnectionStage(proxyCheckDiagnostic.c_str());
        if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_negative_cache_hit host=%s key=%s", this, host.c_str(), proxyHandshakeAdmissionKey.c_str());
        closeSocket(1, -1);
        return;
    }
    publishProxyConnectionStage("host_resolve_start");
    if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup host_resolve_start admission_mode=%s connection_pattern=%s host=%s key=%s", this, mtProxyConnectionPatternModeName(currentConnectionPatternMode), mtProxyConnectionPatternModeName(currentConnectionPatternMode), host.c_str(), proxyHandshakeAdmissionKey.c_str());
    setMtProxyDnsResolveAttemptStarted(true, "host_resolve_start");
    setTransportState(TransportState::WaitingGate, "host_resolve_start");
    manager.delegate->getHostByName(host, instanceNum, this);
#endif
}

void ConnectionSocket::onHostNameResolved(std::string host, std::string ip, bool ipv6) {
    ConnectionsManager::getInstance(instanceNum).scheduleTask([&, host, ip, ipv6] {
        checkHostResolveCallback(host);
        if (waitingForHostResolve == host) {
            setWaitingForHostResolve("", "host_resolve_callback");
            setMtProxyDnsResolveAttemptStarted(false, "host_resolve_callback");
            setMtProxyPreTcpWaitPhase(MtProxyStartupPhase::None, 0, "host_resolve_callback");
            if (ip == "dns_negative_cache_hit") {
                proxyCheckDiagnostic = "dns_negative_cache_hit";
                publishProxyConnectionStage(proxyCheckDiagnostic.c_str());
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup dns_negative_cache_hit host=%s callback=1", this, host.c_str());
                closeSocket(1, -1);
                return;
            }
            if (ip == "dns_blocked_zero_address" || mtProxyIsBlockedZeroAddress(ip)) {
                closeMtProxyDnsBlockedZeroAddress(host, ip, "host_resolve_callback");
                return;
            }
            if (ip.empty() || inet_pton(AF_INET, ip.c_str(), &socketAddress.sin_addr.s_addr) != 1) {
                bool cachedIpv6 = ipv6;
                bool blockedZeroAddress = false;
                if (mtProxyEndpointUseCachedHostAddress(host, &cachedIpv6, &blockedZeroAddress)) {
                    openConnectionInternal(cachedIpv6);
                    return;
                }
                if (blockedZeroAddress) {
                    return;
                }
                proxyCheckDiagnostic = "host_resolve_failed";
                publishProxyConnectionStage(proxyCheckDiagnostic.c_str());
                if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup host_resolve_failed host=%s ip=%s", this, host.c_str(), ip.c_str());
                if (LOGS_ENABLED) DEBUG_E("connection(%p) can't resolve host %s address via delegate", this, host.c_str());
                closeSocket(1, -1);
                return;
            }
            mtProxyEndpointStoreResolvedAddress(host, ip);
            if (LOGS_ENABLED) DEBUG_D("connection(%p) resolved host %s address %s via delegate", this, host.c_str(), ip.c_str());
            openConnectionInternal(ipv6);
        }
    });
}
