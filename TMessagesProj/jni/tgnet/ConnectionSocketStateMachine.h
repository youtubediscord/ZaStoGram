/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#ifndef CONNECTIONSOCKETSTATEMACHINE_H
#define CONNECTIONSOCKETSTATEMACHINE_H

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>
#include <memory>
#include <string>
#include "WssTransport.h"

class ByteArray;
class ByteStream;
class EventObject;
class NativeByteBuffer;
class Timer;

class ConnectionSocketStateMachine {
public:
    enum class LifecycleState : uint8_t {
        Idle,
        Prepared,
        WaitingGate,
        TcpConnecting,
        EpollRegistered,
        ProxyHandshake,
        FakeTlsHandshake,
        FaketlsHandshake = FakeTlsHandshake,
        MtprotoReady,
        Closing,
    };

    enum class TransportMode : uint8_t {
        None,
        Direct,
        Socks5,
        PlainMtProxy,
        FakeTlsMtProxy,
        Wss,
    };

    enum class TransportSocketPolicy : uint8_t {
        None,
        NoSocket,
        LiveEpoll,
        OpenWithoutEpoll,
    };

    struct ActionRule {
        const char *action;
        LifecycleState state;
        TransportSocketPolicy socketPolicy;
        int16_t expectedProxyAuthState;
        int16_t expectedTlsState;
        bool requireWssTransport;
        bool requireWssReady;
    };

    struct SocketSubstate {
        int fd = -1;
        struct epoll_event eventMask;
        struct sockaddr_in address;
        struct sockaddr_in6 address6;
        bool isIpv6 = false;
        time_t timeout = 12;
        int64_t lastEventTime = 0;
        EventObject *eventObject = nullptr;
        ByteStream *outgoingByteStream = nullptr;
        int32_t currentNetworkType = 0;
        std::string currentAddress;
        uint16_t currentPort = 0;
        std::string currentSocksUsername;
        std::string currentSocksPassword;
    };

    struct EpollSubstate {
        bool registered = false;
    };

    struct HostResolveSubstate {
        std::string waitingHost;
        bool adjustWriteAfterResolve = false;
    };

    struct NotificationSubstate {
        bool connectedSent = false;
        bool closeNotified = false;
        bool closeDiagnosticSuppressed = false;
        bool mtproxySocketConnectedLogged = false;
    };

    struct SocksSubstate {
        uint8_t proxyAuthState = 0;
    };

    struct FakeTlsSubstate {
        int8_t tlsState = 0;
        bool tlsHashMismatch = false;
        bool serverHelloHmacMismatchObserved = false;
        int64_t serverHelloHmacMismatchTime = 0;
        bool tlsBufferSized = true;
        uint8_t tlsBufferRecordType = 0;
        NativeByteBuffer *tlsBuffer = nullptr;
        ByteArray *pendingClientHello = nullptr;
        uint32_t pendingClientHelloSize = 0;
        uint32_t pendingClientHelloOffset = 0;
        uint32_t pendingClientHelloFragmentTarget = 0;
        uint32_t pendingClientHelloFragmentIndex = 0;
        uint32_t pendingClientHelloFragmentCount = 0;
        int64_t pendingClientHelloNextWriteTime = 0;
        ByteArray *pendingTlsFrame = nullptr;
        uint32_t pendingTlsFrameSize = 0;
        uint32_t pendingTlsFrameOffset = 0;
        uint32_t pendingTlsPayloadSize = 0;
        int64_t nextTlsFrameWriteTime = 0;
        bool mtproxyFirstTlsFrameSentLogged = false;
        bool mtproxyFirstTlsDataReceivedLogged = false;
        bool mtproxyFirstPlainDataSentLogged = false;
        bool mtproxyFirstPlainDataReceivedLogged = false;
        int64_t mtproxyFirstTlsFrameSentTime = 0;
        int64_t mtproxyFirstPlainDataSentTime = 0;
        int64_t mtproxyFirstDataReceivedTime = 0;
        uint32_t mtproxyTlsFrameCompletedCount = 0;
    };

    struct WssSubstate {
        bool active = false;
        int32_t datacenterId = 0;
        bool mediaConnection = false;
        WssRouteConfig route;
        std::unique_ptr<WssTransport> transport;
    };

    struct AdmissionSubstate {
        Timer *timer = nullptr;
        bool queued = false;
        bool queuePublished = false;
        bool active = false;
        bool ready = false;
        bool ipv6 = false;
        uint32_t generation = 0;
        uint32_t timerGeneration = 0;
        int32_t priority = 0;
        int32_t timerMode = 0;
        int64_t startTime = 0;
        int64_t clientHelloSentTime = 0;
        std::string key;
    };

    struct EndpointGateSubstate {
        bool backoffReady = false;
        bool tcpConnectActive = false;
        bool tcpConnectReady = false;
        bool tcpConnectGatePublished = false;
        bool dnsCoalesceReady = false;
    };

    struct PendingWriteSubstate {
        ByteArray *tempBuffer = nullptr;
        size_t bytesRead = 0;
        int64_t startupCoverStartTime = 0;
        uint32_t startupCoverFrameCount = 0;
        bool startupCoverStartedLogged = false;
        bool startupCoverEndedLogged = false;
        bool adjustWriteAfterPreTcpGate = false;
    };

    struct DiagnosticsSubstate {
        LifecycleState lifecycle = LifecycleState::Idle;
        TransportMode transportMode = TransportMode::None;
        std::string currentSecret;
        std::string currentSecretDomain;
        const char *currentSecretKind = "none";
        bool currentSecretIsFakeTls = false;
        int32_t currentProxyTlsProfile = 0;
        int32_t currentEffectiveProxyTlsProfile = 0;
        int32_t currentClientHelloFragmentation = 0;
        int32_t currentConnectionPatternMode = 0;
        int32_t currentRecordSizingMode = 0;
        int32_t currentTimingMode = 0;
        int32_t currentStartupCoverMode = 0;
        std::string currentProxyTlsProfileKey;
        std::string currentMtProxyEndpointKey;
        std::string currentMtProxyNetworkEndpointKey;
        std::string currentMtProxyDnsCacheKey;
        std::string proxyCheckDiagnostic = "connection_not_started";
        bool tcpConnectAttemptStarted = false;
        bool dnsResolveAttemptStarted = false;
        std::string preTcpWaitPhase;
        int64_t preTcpWaitDeadlineMs = 0;
    };

    SocketSubstate socket;
    EpollSubstate epoll;
    HostResolveSubstate hostResolve;
    NotificationSubstate notification;
    SocksSubstate socks;
    FakeTlsSubstate fakeTls;
    WssSubstate wss;
    AdmissionSubstate admission;
    EndpointGateSubstate endpointGate;
    PendingWriteSubstate pendingWrite;
    DiagnosticsSubstate diagnostics;

    const char *lifecycleName(LifecycleState state) const;
    const char *transportModeName(TransportMode mode) const;
    const ActionRule *findActionRule(const char *action) const;
    bool can(const char *action) const;
    bool isAllowedTransition(LifecycleState previous, LifecycleState next) const;
    void setLifecycle(LifecycleState next);
    void setTransportMode(TransportMode mode);
    bool setSocketFd(int fd);
    bool setEpollRegistered(bool registered);
    bool setProxyAuthState(uint8_t state);
    bool setTlsState(int8_t state);
    int createNativeSocket(int domain, int type, int protocol);
    bool closeNativeSocket(const char *reason);
    bool connectNativeSocket(const sockaddr *address, socklen_t addressLen);
    bool epollCtlAdd(int epollFd);
    bool epollCtlMod(int epollFd);
    bool epollCtlDel(int epollFd);
    ssize_t sendBytes(const void *bytes, size_t size, int flags);
    ssize_t recvBytes(void *bytes, size_t size, int flags);
};

#endif
