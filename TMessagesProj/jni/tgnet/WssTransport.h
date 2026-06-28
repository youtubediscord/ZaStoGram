/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#ifndef WSSTRANSPORT_H
#define WSSTRANSPORT_H

#include <stdint.h>
#include <string>
#include <vector>
#include <openssl/ssl.h>

struct WssRouteConfig {
    int32_t mode = 0;
    int32_t gatewayMode = 0;
    std::string relayIp;
    uint16_t relayPort = 443;
    std::string domain;
    std::string path = "/apiws";
    std::string targetAddress;
    uint16_t targetPort = 443;
    std::string upstreamSocksAddress;
    uint16_t upstreamSocksPort = 1080;
    std::string upstreamSocksUsername;
    std::string upstreamSocksPassword;
    bool upstreamSocksEnabled = false;
};

class WssTransport {

public:
    static constexpr int32_t WSS_TRANSPORT_OFF = 0;
    static constexpr int32_t WSS_TRANSPORT_OFFICIAL = 1;
    static constexpr int32_t WSS_TRANSPORT_CUSTOM = 2;
    static constexpr int32_t WSS_TRANSPORT_SOCKS5 = 3;

    WssTransport();
    ~WssTransport();

    bool connect(int socketFd, const WssRouteConfig &routeConfig);
    bool onReadable(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic);
    bool onWritable(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic);
    bool sendFrame(const uint8_t *data, uint32_t size);
    bool isReady() const;
    bool wantsWrite() const;
    bool isClosed() const;
    const WssRouteConfig &route() const;

    static WssRouteConfig officialRouteFor(int32_t dcId, bool isMedia);
    static WssRouteConfig customRoute(
            int32_t mode,
            int32_t gatewayMode,
            const std::string &host,
            uint16_t port,
            const std::string &path,
            const std::string &targetAddress,
            uint16_t targetPort,
            const std::string &upstreamSocksAddress,
            uint16_t upstreamSocksPort,
            const std::string &upstreamSocksUsername,
            const std::string &upstreamSocksPassword,
            bool upstreamSocksEnabled);

private:
    enum class State {
        TcpSocksGreetingWrite,
        TcpSocksGreetingRead,
        TcpSocksPasswordAuthWrite,
        TcpSocksPasswordAuthRead,
        TcpSocksConnectWrite,
        TcpSocksConnectRead,
        TlsHandshake,
        HttpWrite,
        HttpRead,
        Ready,
        Closed,
    };

    WssRouteConfig config;
    SSL *ssl = nullptr;
    int fd = -1;
    State state = State::Closed;
    std::vector<uint8_t> pendingOutput;
    size_t pendingOutputOffset = 0;
    std::vector<uint8_t> inputBuffer;

    bool pump(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic);
    bool pumpTls(std::string *diagnostic);
    bool queueHttpUpgrade();
    bool buildSocks5Greeting(std::vector<uint8_t> &out, bool allowPassword) const;
    bool buildSocks5PasswordAuth(std::vector<uint8_t> &out) const;
    bool buildSocks5Connect(std::vector<uint8_t> &out, const std::string &host, uint16_t port) const;
    bool flushPending(std::string *diagnostic);
    bool readIntoBuffer(std::string *diagnostic);
    bool readRawIntoBuffer(std::string *diagnostic);
    bool isTcpSocksWriteState() const;
    bool isTcpSocksReadState() const;
    bool parseRawSocksGreetingResponse(std::string *diagnostic, bool &passwordSelected);
    bool parseRawSocksPasswordAuthResponse(std::string *diagnostic);
    bool parseRawSocksConnectResponse(std::string *diagnostic);
    bool parseHttpResponse(std::string *diagnostic);
    bool parseWebSocketFrames(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic);
    void queueWebSocketFrame(uint8_t opcode, const uint8_t *data, uint32_t size);
    void closeTransport();
};

#endif
