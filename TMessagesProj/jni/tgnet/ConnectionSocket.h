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
#include <string>

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
    void openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType);
    void setTimeout(time_t timeout);
    time_t getTimeout();
    bool isDisconnected();
    void dropConnection();
    void setOverrideProxy(std::string address, uint16_t port, std::string username, std::string password, std::string secret);
    void onHostNameResolved(std::string host, std::string ip, bool ipv6);

protected:
    int32_t instanceNum;
    void onEvent(uint32_t events);
    bool checkTimeout(int64_t now);
    void resetLastEventTime();
    bool hasTlsHashMismatch();
    virtual void onReceivedData(NativeByteBuffer *buffer) = 0;
    virtual void onDisconnected(int32_t reason, int32_t error) = 0;
    virtual void onConnected() = 0;
    virtual bool hasPendingRequests() = 0;

    std::string overrideProxyUser = "";
    std::string overrideProxyPassword = "";
    std::string overrideProxyAddress = "";
    std::string overrideProxySecret = "";
    uint16_t overrideProxyPort = 1080;

private:
    ByteStream *outgoingByteStream = nullptr;
    struct epoll_event eventMask;
    struct sockaddr_in socketAddress;
    struct sockaddr_in6 socketAddress6;
    int socketFd = -1;
    time_t timeout = 12;
    bool onConnectedSent = false;
    int64_t lastEventTime = 0;
    EventObject *eventObject;
    int32_t currentNetworkType;
    bool isIpv6;
    std::string currentAddress;
    uint16_t currentPort;

    std::string waitingForHostResolve;
    bool adjustWriteOpAfterResolve;

    std::string currentSecret;
    std::string currentSecretDomain;

    bool tlsHashMismatch = false;
    bool tlsBufferSized = true;
    NativeByteBuffer *tlsBuffer = nullptr;
    ByteArray *tempBuffer = nullptr;
    size_t bytesRead = 0;
    int8_t tlsState = 0;
    uint32_t tlsRecordRemaining = 0; // payload bytes still owed for the in-flight TLS record

    // DRS (dynamic record sizing): per-connection state so outgoing TLS application_data
    // records vary in size like a real browser's congestion ramp instead of a fixed cap.
    int8_t drsPhase = 0;            // 0 = slow-start, 1 = congestion-open, 2 = steady-state
    uint32_t drsRecordsInPhase = 0;
    uint32_t drsBytesInPhase = 0;
    uint32_t drsLastCap = 0;
    int8_t drsLastDir = 0;          // +1 grew, -1 shrank, 0 unknown
    int64_t drsLastWriteTime = 0;
    uint32_t drsIdleResetMs = 0;

    // Non-blocking pacing: stagger bursts of proxy connects via a one-shot timer instead of a
    // blocking sleep, so the shared network thread (and active transfers) is never stalled.
    Timer *pacingTimer = nullptr;
    bool pacingDeferred = false; // true between scheduling the delay and the resumed connect
    bool pacingIpv6 = false;     // remembers openConnectionInternal's arg across the delay

    uint8_t proxyAuthState;

    int32_t checkSocketError(int32_t *error);
    void closeSocket(int32_t reason, int32_t error);
    void openConnectionInternal(bool ipv6);
    void adjustWriteOp();
    uint32_t nextTlsRecordSize();

    friend class EventObject;
    friend class ConnectionsManager;
    friend class Connection;
};

#endif
