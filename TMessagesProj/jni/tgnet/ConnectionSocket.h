/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2015-2018.
 */

#ifndef CONNECTIONSOCKET_H
#define CONNECTIONSOCKET_H

#include <sys/epoll.h>
#include <netinet/in.h>
#include <memory>
#include <string>
#include "ConnectionSocketStateMachine.h"
#include "MtProxyOptions.h"

class NativeByteBuffer;
class ConnectionsManager;
class ByteStream;
class EventObject;
class ByteArray;
class Timer;
class ConnectionSocket {

public:
    ConnectionSocket(int32_t instance);
    virtual ~ConnectionSocket();

    void writeBuffer(uint8_t *data, uint32_t size);
    void writeBuffer(NativeByteBuffer *buffer);
    void openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType, int32_t datacenterId = 0, bool mediaConnection = false);
    void setTimeout(time_t timeout);
    time_t getTimeout();
    int32_t getCurrentNetworkType() const;
    bool isDisconnected();
    bool isCurrentMtProxyConnection();
    void dropConnection();
    void setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret, const MtProxyOptions &options);
    void onHostNameResolved(std::string host, std::string ip, bool ipv6);
    void setMtProxyHandshakePriority(int32_t priority);
    const char *getProxyCheckDiagnostic();
    bool isProxyCloseDiagnosticSuppressed();

protected:
    int32_t instanceNum;
    void onEvent(uint32_t events);
    bool checkTimeout(int64_t now);
    void resetLastEventTime();
    bool hasTlsHashMismatch();
    void publishProxyConnectionStage(const char *diagnostic);
    void markMtProxyFirstPlainDataSent(uint32_t bytes);
    void markMtProxyFirstPlainDataReceived(uint32_t bytes);
    virtual void onReceivedData(NativeByteBuffer *buffer) = 0;
    virtual void onDisconnected(int32_t reason, int32_t error) = 0;
    virtual void onConnected() = 0;
    virtual bool hasPendingRequests() = 0;

    std::string overrideProxyUser = "";
    std::string overrideProxyPassword = "";
    std::string overrideProxyAddress = "";
    std::string overrideProxySecret = "";
    uint16_t overrideProxyPort = 1080;
    MtProxyOptions overrideMtProxyOptions;

private:
    using TransportState = ConnectionSocketStateMachine::LifecycleState;
    using TransportMode = ConnectionSocketStateMachine::TransportMode;
    using TransportSocketPolicy = ConnectionSocketStateMachine::TransportSocketPolicy;
    using TransportActionRule = ConnectionSocketStateMachine::ActionRule;

    ConnectionSocketStateMachine stateMachine;

    int32_t checkSocketError(int32_t *error);
    void closeSocket(int32_t reason, int32_t error);
    void openConnectionInternal(bool ipv6);
    void queueAdjustWriteOpAfterOutboundAppend(const char *reason);
    void adjustWriteOp();
    const char *transportStateName(TransportState state);
    bool isAllowedTransportTransition(TransportState previous, TransportState next);
    void setTransportState(TransportState next, const char *reason);
    const char *proxyAuthStateName(uint8_t state);
    bool isAllowedProxyAuthTransition(uint8_t previous, uint8_t next);
    void setProxyAuthState(uint8_t next, const char *reason);
    const char *tlsStateName(int8_t state);
    bool isAllowedTlsStateTransition(int8_t previous, int8_t next);
    void setTlsState(int8_t next, const char *reason);
    void logTransportSnapshot(const char *event, const char *reason);
    void logTransportInvariant(const char *action, const char *reason);
    const TransportActionRule *findTransportActionRule(const char *action);
    bool isTransportStateAllowedForAction(const char *action);
    bool checkTransportActionRequirements(const char *action);
    void setSocketFd(int fd, const char *reason);
    void setEpollRegistered(bool registered, const char *reason);
    bool canCreateSocket(const char *action);
    bool canUseLiveEpollSocket(const char *action);
    bool canModifyEpollWriteInterest(const char *action);
    bool canSendPendingClientHello();
    bool canSendPendingTlsFrame();
    bool canSendSocksHandshakeFrame(const char *action, uint8_t expectedProxyAuthState);
    bool canSendPlainMtProtoPayload();
    bool canStartTcpConnect();
    bool canRegisterEpollSocket();
    bool canConfigureOpenSocket();
    bool canCheckSocketError();
    bool canProcessEpollEvent();
    void checkCloseSocketAction(const char *action);
    bool canUnregisterEpollSocket();
    bool canCloseNativeSocket();
    void setProxyHandshakeAdmissionState(int8_t queued, int8_t published, int8_t active, int8_t ready, const char *reason);
    void checkProxyHandshakeAdmissionRelease(bool succeeded, const char *reason);
    void setProxyEndpointTcpConnectGateState(int8_t active, int8_t ready, int8_t published, const char *reason);
    void setProxyEndpointBackoffReady(bool ready, const char *reason);
    void setProxyEndpointDnsCoalesceReady(bool ready, const char *reason);
    void setAdjustWriteOpAfterResolve(bool pending, const char *reason);
    void setAdjustWriteOpAfterPreTcpGate(bool pending, const char *reason);
    void setMtProxyTcpConnectAttemptStarted(bool started, const char *reason);
    void setMtProxyDnsResolveAttemptStarted(bool started, const char *reason);
    void setMtProxyPreTcpWaitPhase(const char *phase, int64_t deadlineMs, const char *reason);
    void classifyMtProxyPreTcpTimeoutDiagnostic(const char *reason);
    std::string deriveMtProxyTerminalDiagnostic(int32_t reason, int32_t error);
    bool mtProxyDiagnosticIsLocalSchedulerTimeout(const char *diagnostic);
    void setMtProxySocketConnectedLogged(bool logged, const char *reason);
    bool canStartHostResolve();
    void checkHostResolveCallback(const std::string &host);
    void setWaitingForHostResolve(const std::string &host, const char *reason);
    bool canNotifyConnected(const char *action);
    void setSocketCloseNotified(bool notified, const char *reason);
    void setConnectedNotified(bool sent, const char *reason);
    bool canDeliverReceivedData(const char *action);
    bool canSendWssFrame();
    bool canQueueOutboundBuffer(const char *action);
    bool canSendRawSocketBytes(const char *action);
    bool canReceiveRawSocketBytes();
    bool isCurrentTransportWss();
    bool dispatchWssPayloads(std::vector<std::vector<uint8_t>> &payloads);
    bool scheduleProxyHandshakeAdmissionIfNeeded(bool ipv6, int32_t timerMode);
    void scheduleProxyHandshakeAdmissionTimer(uint32_t delay, int32_t mode, bool ipv6);
    void grantProxyHandshakeAdmission(bool ipv6, uint32_t generation, uint32_t delay, int32_t timerMode, const char *reason);
    void requestPendingHostResolve();
    void cancelProxyHandshakeAdmission();
    void releaseProxyHandshakeAdmission(bool succeeded, const char *reason);
    bool scheduleMtProxyEndpointCircuitBreakerIfNeeded(bool ipv6);
    bool scheduleMtProxyEndpointTcpConnectGateIfNeeded(bool ipv6);
    void releaseMtProxyEndpointTcpConnect(const char *reason);
    bool scheduleMtProxyDnsCoalesceIfNeeded(bool ipv6);
    void recordMtProxyEndpointFailure(const char *diagnostic, const char *reason);
    void recordMtProxyEndpointHandshakeOk(const char *reason);
    void recordMtProxyEndpointDataPathSuccess(const char *reason);
    bool mtProxyEndpointUseCachedHostAddress(const std::string &host, bool *ipv6);
    void mtProxyEndpointStoreResolvedAddress(const std::string &host, const std::string &ip);
    void applyMtProxyPhaseAdaptiveRecipe();
    void rotateMtProxyTlsProfileOnFailureIfNeeded(int32_t reason, int32_t error);
    void markProxyHandshakeClientHelloSent();
    void markProxyHandshakeFreezeIfNeeded();
    void markProxyServerHelloHmacTimeoutIfNeeded();
    void clearPendingClientHello();
    bool buildPendingClientHello(uint32_t size);
    bool sendPendingClientHelloFragment(uint32_t limit);
    bool sendPendingClientHello();
    void clearPendingTlsFrame();
    bool buildPendingTlsFrame(NativeByteBuffer *buffer, uint32_t remaining);
    bool sendPendingTlsFrame();
    uint32_t nextMtProxyTlsRecordPayloadSize(uint32_t remaining);
    bool scheduleMtProxyDataTimingIfNeeded();
    void startMtProxyStartupCover();
    bool mtProxyStartupCoverActive();
    int32_t effectiveMtProxyRecordSizingMode();
    int32_t effectiveMtProxyTimingMode();

    friend class EventObject;
    friend class ConnectionsManager;
    friend class Connection;
};

#endif
