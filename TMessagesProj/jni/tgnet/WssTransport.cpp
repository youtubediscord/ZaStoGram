/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "WssTransport.h"
#include "FileLog.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>

static constexpr const char *OFFICIAL_WSS_RELAY_IP = "149.154.167.220";
static constexpr const char *OFFICIAL_WSS_PATH = "/apiws";
static constexpr uint32_t WSS_MAX_FRAME = 2 * 1024 * 1024;

static SSL_CTX *wssSslContext() {
    static SSL_CTX *ctx = [] {
        SSL_CTX *created = SSL_CTX_new(TLS_client_method());
        if (created != nullptr) {
            SSL_CTX_set_verify(created, SSL_VERIFY_NONE, nullptr);
            SSL_CTX_set_options(created, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        }
        return created;
    }();
    return ctx;
}

static std::string base64Encode(const uint8_t *data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t chunk = ((uint32_t) data[i]) << 16;
        if (i + 1 < len) {
            chunk |= ((uint32_t) data[i + 1]) << 8;
        }
        if (i + 2 < len) {
            chunk |= data[i + 2];
        }
        out.push_back(alphabet[(chunk >> 18) & 0x3f]);
        out.push_back(alphabet[(chunk >> 12) & 0x3f]);
        out.push_back(i + 1 < len ? alphabet[(chunk >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < len ? alphabet[chunk & 0x3f] : '=');
    }
    return out;
}

static std::string normalizeWssPath(const std::string &path) {
    if (path.empty()) {
        return OFFICIAL_WSS_PATH;
    }
    if (path[0] == '/') {
        return path;
    }
    return "/" + path;
}

static bool isIpv4(const std::string &host, uint8_t out[4]) {
    return inet_pton(AF_INET, host.c_str(), out) == 1;
}

static bool isIpv6(const std::string &host, uint8_t out[16]) {
    return inet_pton(AF_INET6, host.c_str(), out) == 1;
}

WssTransport::WssTransport() = default;

WssTransport::~WssTransport() {
    closeTransport();
}

WssRouteConfig WssTransport::officialRouteFor(int32_t dcId, bool isMedia) {
    WssRouteConfig route;
    if (dcId != 2 && dcId != 4) {
        route.mode = WSS_TRANSPORT_OFF;
        return route;
    }
    route.mode = WSS_TRANSPORT_OFFICIAL;
    route.gatewayMode = 0;
    route.relayIp = OFFICIAL_WSS_RELAY_IP;
    route.relayPort = 443;
    route.path = OFFICIAL_WSS_PATH;

    if (dcId == 4) {
        route.domain = isMedia ? "kws4-1.web.telegram.org" : "kws4.web.telegram.org";
    } else {
        route.domain = isMedia ? "kws2-1.web.telegram.org" : "kws2.web.telegram.org";
    }
    return route;
}

WssRouteConfig WssTransport::customRoute(
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
        bool upstreamSocksEnabled) {
    WssRouteConfig route;
    route.mode = mode;
    route.gatewayMode = gatewayMode;
    route.relayIp = host;
    route.relayPort = port == 0 ? 443 : port;
    route.domain = host;
    route.path = normalizeWssPath(path);
    route.targetAddress = targetAddress;
    route.targetPort = targetPort;
    route.upstreamSocksAddress = upstreamSocksAddress;
    route.upstreamSocksPort = upstreamSocksPort == 0 ? 1080 : upstreamSocksPort;
    route.upstreamSocksUsername = upstreamSocksUsername;
    route.upstreamSocksPassword = upstreamSocksPassword;
    route.upstreamSocksEnabled = upstreamSocksEnabled && !route.upstreamSocksAddress.empty();
    return route;
}

bool WssTransport::connect(int socketFd, const WssRouteConfig &routeConfig) {
    closeTransport();
    SSL_CTX *ctx = wssSslContext();
    if (ctx == nullptr) {
        return false;
    }
    ssl = SSL_new(ctx);
    if (ssl == nullptr) {
        return false;
    }
    fd = socketFd;
    config = routeConfig;
    if (!config.domain.empty()) {
        SSL_set_tlsext_host_name(ssl, config.domain.c_str());
    }
    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);
    pendingOutput.clear();
    pendingOutputOffset = 0;
    inputBuffer.clear();
    if (config.upstreamSocksEnabled) {
        std::vector<uint8_t> greeting;
        if (!buildSocks5Greeting(greeting, true)) {
            return false;
        }
        pendingOutput = std::move(greeting);
        state = State::TcpSocksGreetingWrite;
        if (LOGS_ENABLED) DEBUG_D("wss_tcp_socks start socks=%s:%u domain=%s:%u", config.upstreamSocksAddress.c_str(), (uint32_t) config.upstreamSocksPort, config.domain.c_str(), (uint32_t) config.relayPort);
    } else {
        state = State::TlsHandshake;
    }
    if (LOGS_ENABLED) DEBUG_D("wss_startup transport=connect mode=%d domain=%s path=%s upstream_socks=%s:%u upstream_enabled=%d", config.mode, config.domain.c_str(), config.path.c_str(), config.upstreamSocksAddress.c_str(), (uint32_t) config.upstreamSocksPort, config.upstreamSocksEnabled ? 1 : 0);
    return true;
}

bool WssTransport::onReadable(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic) {
    return pump(payloads, diagnostic);
}

bool WssTransport::onWritable(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic) {
    return pump(payloads, diagnostic);
}

bool WssTransport::sendFrame(const uint8_t *data, uint32_t size) {
    if (state == State::Closed || data == nullptr) {
        return false;
    }
    queueWebSocketFrame(0x2, data, size);
    return true;
}

bool WssTransport::isReady() const {
    return state == State::Ready;
}

bool WssTransport::wantsWrite() const {
    return state == State::TlsHandshake || !pendingOutput.empty();
}

bool WssTransport::isClosed() const {
    return state == State::Closed;
}

const WssRouteConfig &WssTransport::route() const {
    return config;
}

bool WssTransport::pump(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic) {
    if (state == State::Closed) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_closed";
        }
        return false;
    }
    if (!pumpTls(diagnostic)) {
        return false;
    }
    if (!flushPending(diagnostic)) {
        return false;
    }
    if (isTcpSocksReadState()) {
        if (!readRawIntoBuffer(diagnostic)) {
            return false;
        }
    } else if (state == State::HttpRead
            || state == State::Ready) {
        if (!readIntoBuffer(diagnostic)) {
            return false;
        }
    }
    if (state == State::TcpSocksGreetingRead) {
        std::string parseDiagnostic;
        bool passwordSelected = false;
        if (parseRawSocksGreetingResponse(&parseDiagnostic, passwordSelected)) {
            if (passwordSelected) {
                std::vector<uint8_t> auth;
                if (!buildSocks5PasswordAuth(auth)) {
                    if (diagnostic != nullptr) {
                        *diagnostic = "wss_tcp_socks_auth_build_failed";
                    }
                    return false;
                }
                pendingOutput = std::move(auth);
                pendingOutputOffset = 0;
                state = State::TcpSocksPasswordAuthWrite;
            } else {
                std::vector<uint8_t> request;
                const std::string &connectHost = !config.domain.empty() ? config.domain : config.relayIp;
                if (!buildSocks5Connect(request, connectHost, config.relayPort)) {
                    if (diagnostic != nullptr) {
                        *diagnostic = "wss_tcp_socks_connect_build_failed";
                    }
                    return false;
                }
                pendingOutput = std::move(request);
                pendingOutputOffset = 0;
                state = State::TcpSocksConnectWrite;
            }
        } else if (!parseDiagnostic.empty()) {
            if (diagnostic != nullptr) {
                *diagnostic = parseDiagnostic;
            }
            return false;
        }
    }
    if (state == State::TcpSocksPasswordAuthRead) {
        std::string parseDiagnostic;
        if (parseRawSocksPasswordAuthResponse(&parseDiagnostic)) {
            std::vector<uint8_t> request;
            const std::string &connectHost = !config.domain.empty() ? config.domain : config.relayIp;
            if (!buildSocks5Connect(request, connectHost, config.relayPort)) {
                if (diagnostic != nullptr) {
                    *diagnostic = "wss_tcp_socks_connect_build_failed";
                }
                return false;
            }
            pendingOutput = std::move(request);
            pendingOutputOffset = 0;
            state = State::TcpSocksConnectWrite;
        } else if (!parseDiagnostic.empty()) {
            if (diagnostic != nullptr) {
                *diagnostic = parseDiagnostic;
            }
            return false;
        }
    }
    if (state == State::TcpSocksConnectRead) {
        std::string parseDiagnostic;
        if (parseRawSocksConnectResponse(&parseDiagnostic)) {
            inputBuffer.clear();
            state = State::TlsHandshake;
            if (LOGS_ENABLED) DEBUG_D("wss_tcp_socks connect_ok socks=%s:%u domain=%s:%u", config.upstreamSocksAddress.c_str(), (uint32_t) config.upstreamSocksPort, config.domain.c_str(), (uint32_t) config.relayPort);
            if (!pumpTls(diagnostic)) {
                return false;
            }
        } else if (!parseDiagnostic.empty()) {
            if (diagnostic != nullptr) {
                *diagnostic = parseDiagnostic;
            }
            return false;
        }
    }
    if (state == State::HttpRead) {
        std::string parseDiagnostic;
        if (parseHttpResponse(&parseDiagnostic)) {
            state = State::Ready;
            if (LOGS_ENABLED) DEBUG_D("wss_startup http_upgrade_ok domain=%s path=%s", config.domain.c_str(), config.path.c_str());
        } else if (!parseDiagnostic.empty()) {
            if (diagnostic != nullptr) {
                *diagnostic = parseDiagnostic;
            }
            return false;
        }
    }
    if (state == State::Ready) {
        return parseWebSocketFrames(payloads, diagnostic);
    }
    return true;
}

bool WssTransport::pumpTls(std::string *diagnostic) {
    if (state != State::TlsHandshake) {
        return true;
    }
    int rc = SSL_connect(ssl);
    if (rc == 1) {
        if (!queueHttpUpgrade()) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_http_request_build_failed";
            }
            return false;
        }
        state = State::HttpWrite;
        return true;
    }
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return true;
    }
    if (diagnostic != nullptr) {
        *diagnostic = "wss_tls_failed";
    }
    return false;
}

bool WssTransport::queueHttpUpgrade() {
    uint8_t randomKey[16];
    if (RAND_bytes(randomKey, sizeof(randomKey)) != 1) {
        return false;
    }
    std::string wsKey = base64Encode(randomKey, sizeof(randomKey));
    std::string path = normalizeWssPath(config.path);
    std::string host = config.domain;
    if (config.relayPort != 443) {
        host += ":" + std::to_string((uint32_t) config.relayPort);
    }
    std::string request =
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + wsKey + "\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: binary\r\n"
            "Origin: https://web.telegram.org\r\n"
            "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36\r\n"
            "\r\n";
    pendingOutput.assign(request.begin(), request.end());
    pendingOutputOffset = 0;
    return true;
}

bool WssTransport::buildSocks5Greeting(std::vector<uint8_t> &out, bool allowPassword) const {
    out.clear();
    out.push_back(0x05);
    if (allowPassword && (!config.upstreamSocksUsername.empty() || !config.upstreamSocksPassword.empty())) {
        out.push_back(0x02);
        out.push_back(0x00);
        out.push_back(0x02);
    } else {
        out.push_back(0x01);
        out.push_back(0x00);
    }
    return true;
}

bool WssTransport::buildSocks5PasswordAuth(std::vector<uint8_t> &out) const {
    out.clear();
    if (config.upstreamSocksUsername.size() > 255 || config.upstreamSocksPassword.size() > 255) {
        return false;
    }
    out.push_back(0x01);
    out.push_back((uint8_t) config.upstreamSocksUsername.size());
    out.insert(out.end(), config.upstreamSocksUsername.begin(), config.upstreamSocksUsername.end());
    out.push_back((uint8_t) config.upstreamSocksPassword.size());
    out.insert(out.end(), config.upstreamSocksPassword.begin(), config.upstreamSocksPassword.end());
    return true;
}

bool WssTransport::buildSocks5Connect(std::vector<uint8_t> &out, const std::string &host, uint16_t port) const {
    out.clear();
    uint8_t ipv4[4];
    uint8_t ipv6[16];
    out.push_back(0x05);
    out.push_back(0x01);
    out.push_back(0x00);
    if (isIpv4(host, ipv4)) {
        out.push_back(0x01);
        out.insert(out.end(), ipv4, ipv4 + 4);
    } else if (isIpv6(host, ipv6)) {
        out.push_back(0x04);
        out.insert(out.end(), ipv6, ipv6 + 16);
    } else {
        if (host.size() > 255) {
            return false;
        }
        out.push_back(0x03);
        out.push_back((uint8_t) host.size());
        out.insert(out.end(), host.begin(), host.end());
    }
    out.push_back((uint8_t) ((port >> 8) & 0xff));
    out.push_back((uint8_t) (port & 0xff));
    return true;
}

bool WssTransport::flushPending(std::string *diagnostic) {
    while (!pendingOutput.empty() && pendingOutputOffset < pendingOutput.size()) {
        int rc;
        if (isTcpSocksWriteState()) {
            rc = (int) ::send(fd, pendingOutput.data() + pendingOutputOffset, pendingOutput.size() - pendingOutputOffset, 0);
        } else {
            rc = SSL_write(ssl, pendingOutput.data() + pendingOutputOffset, (int) (pendingOutput.size() - pendingOutputOffset));
        }
        if (rc > 0) {
            pendingOutputOffset += (size_t) rc;
            continue;
        }
        if (isTcpSocksWriteState()) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return true;
            }
        } else {
            int err = SSL_get_error(ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return true;
            }
        }
        if (diagnostic != nullptr) {
            *diagnostic = "wss_write_failed";
        }
        return false;
    }
    if (!pendingOutput.empty() && pendingOutputOffset >= pendingOutput.size()) {
        pendingOutput.clear();
        pendingOutputOffset = 0;
        if (state == State::HttpWrite) {
            state = State::HttpRead;
        } else if (state == State::TcpSocksGreetingWrite) {
            state = State::TcpSocksGreetingRead;
        } else if (state == State::TcpSocksPasswordAuthWrite) {
            state = State::TcpSocksPasswordAuthRead;
        } else if (state == State::TcpSocksConnectWrite) {
            state = State::TcpSocksConnectRead;
        }
    }
    return true;
}

bool WssTransport::isTcpSocksWriteState() const {
    return state == State::TcpSocksGreetingWrite
            || state == State::TcpSocksPasswordAuthWrite
            || state == State::TcpSocksConnectWrite;
}

bool WssTransport::isTcpSocksReadState() const {
    return state == State::TcpSocksGreetingRead
            || state == State::TcpSocksPasswordAuthRead
            || state == State::TcpSocksConnectRead;
}

bool WssTransport::readRawIntoBuffer(std::string *diagnostic) {
    uint8_t buffer[1024];
    while (true) {
        ssize_t rc = ::recv(fd, buffer, sizeof(buffer), 0);
        if (rc > 0) {
            inputBuffer.insert(inputBuffer.end(), buffer, buffer + rc);
            continue;
        }
        if (rc == 0) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_tcp_socks_recv_eof";
            }
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return true;
        }
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_read_failed";
        }
        return false;
    }
}

bool WssTransport::readIntoBuffer(std::string *diagnostic) {
    uint8_t buffer[16384];
    while (true) {
        int rc = SSL_read(ssl, buffer, sizeof(buffer));
        if (rc > 0) {
            inputBuffer.insert(inputBuffer.end(), buffer, buffer + rc);
            continue;
        }
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return true;
        }
        if (rc == 0 || err == SSL_ERROR_ZERO_RETURN) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_recv_eof";
            }
            return false;
        }
        if (diagnostic != nullptr) {
            *diagnostic = "wss_read_failed";
        }
        return false;
    }
}

bool WssTransport::parseHttpResponse(std::string *diagnostic) {
    auto it = std::search(inputBuffer.begin(), inputBuffer.end(), "\r\n\r\n", "\r\n\r\n" + 4);
    if (it == inputBuffer.end()) {
        if (inputBuffer.size() > 32 * 1024) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_http_response_too_large";
            }
            return false;
        }
        return false;
    }
    std::string response(inputBuffer.begin(), it);
    size_t consumed = (size_t) (it - inputBuffer.begin()) + 4;
    inputBuffer.erase(inputBuffer.begin(), inputBuffer.begin() + consumed);
    if (response.find(" 101 ") == std::string::npos && response.find(" 101\r") == std::string::npos) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_http_upgrade_failed";
        }
        return false;
    }
    return true;
}

bool WssTransport::parseRawSocksGreetingResponse(std::string *diagnostic, bool &passwordSelected) {
    passwordSelected = false;
    if (inputBuffer.size() < 2) {
        return false;
    }
    if (inputBuffer[0] != 0x05) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_auth_failed";
        }
        return false;
    }
    uint8_t method = inputBuffer[1];
    if (method == 0x02) {
        passwordSelected = true;
    } else if (method != 0x00) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_auth_method_failed";
        }
        return false;
    }
    inputBuffer.erase(inputBuffer.begin(), inputBuffer.begin() + 2);
    return true;
}

bool WssTransport::parseRawSocksPasswordAuthResponse(std::string *diagnostic) {
    if (inputBuffer.size() < 2) {
        return false;
    }
    if (inputBuffer[0] != 0x01 || inputBuffer[1] != 0x00) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_password_auth_failed";
        }
        return false;
    }
    inputBuffer.erase(inputBuffer.begin(), inputBuffer.begin() + 2);
    return true;
}

bool WssTransport::parseRawSocksConnectResponse(std::string *diagnostic) {
    if (inputBuffer.size() < 5) {
        return false;
    }
    if (inputBuffer[0] != 0x05 || inputBuffer[1] != 0x00) {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_connect_failed";
        }
        return false;
    }
    uint8_t atyp = inputBuffer[3];
    size_t total = 0;
    if (atyp == 0x01) {
        total = 10;
    } else if (atyp == 0x04) {
        total = 22;
    } else if (atyp == 0x03) {
        if (inputBuffer.size() < 5) {
            return false;
        }
        total = 7 + inputBuffer[4];
    } else {
        if (diagnostic != nullptr) {
            *diagnostic = "wss_tcp_socks_connect_atyp_failed";
        }
        return false;
    }
    if (inputBuffer.size() < total) {
        return false;
    }
    inputBuffer.erase(inputBuffer.begin(), inputBuffer.begin() + total);
    return true;
}

bool WssTransport::parseWebSocketFrames(std::vector<std::vector<uint8_t>> &payloads, std::string *diagnostic) {
    while (inputBuffer.size() >= 2) {
        uint8_t b0 = inputBuffer[0];
        uint8_t b1 = inputBuffer[1];
        uint8_t opcode = b0 & 0x0f;
        bool masked = (b1 & 0x80) != 0;
        uint64_t len = b1 & 0x7f;
        size_t headerLen = 2;
        if (len == 126) {
            if (inputBuffer.size() < 4) {
                return true;
            }
            len = (((uint64_t) inputBuffer[2]) << 8) | inputBuffer[3];
            headerLen = 4;
        } else if (len == 127) {
            if (inputBuffer.size() < 10) {
                return true;
            }
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | inputBuffer[2 + i];
            }
            headerLen = 10;
        }
        if (len > WSS_MAX_FRAME) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_frame_too_large";
            }
            return false;
        }
        size_t maskLen = masked ? 4 : 0;
        if (inputBuffer.size() < headerLen + maskLen + (size_t) len) {
            return true;
        }
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked) {
            memcpy(mask, inputBuffer.data() + headerLen, 4);
        }
        const uint8_t *payload = inputBuffer.data() + headerLen + maskLen;
        if (opcode == 0x8) {
            if (diagnostic != nullptr) {
                *diagnostic = "wss_close_frame";
            }
            return false;
        } else if (opcode == 0x9) {
            std::vector<uint8_t> pong(payload, payload + len);
            queueWebSocketFrame(0xA, pong.data(), (uint32_t) pong.size());
        } else if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
            std::vector<uint8_t> data(payload, payload + len);
            if (masked) {
                for (size_t i = 0; i < data.size(); i++) {
                    data[i] ^= mask[i % 4];
                }
            }
            if (!data.empty()) {
                payloads.push_back(std::move(data));
            }
        }
        inputBuffer.erase(inputBuffer.begin(), inputBuffer.begin() + headerLen + maskLen + (size_t) len);
    }
    return true;
}

void WssTransport::queueWebSocketFrame(uint8_t opcode, const uint8_t *data, uint32_t size) {
    std::vector<uint8_t> frame;
    frame.reserve(size + 14);
    frame.push_back((uint8_t) (0x80 | opcode));
    if (size < 126) {
        frame.push_back((uint8_t) (0x80 | size));
    } else if (size <= 0xffff) {
        frame.push_back(0x80 | 126);
        frame.push_back((uint8_t) ((size >> 8) & 0xff));
        frame.push_back((uint8_t) (size & 0xff));
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; i--) {
            frame.push_back((uint8_t) ((((uint64_t) size) >> (i * 8)) & 0xff));
        }
    }
    uint8_t mask[4];
    RAND_bytes(mask, sizeof(mask));
    frame.insert(frame.end(), mask, mask + 4);
    for (uint32_t i = 0; i < size; i++) {
        frame.push_back(data[i] ^ mask[i % 4]);
    }
    bool wasEmpty = pendingOutput.empty();
    pendingOutput.insert(pendingOutput.end(), frame.begin(), frame.end());
    if (wasEmpty) {
        pendingOutputOffset = 0;
    }
}

void WssTransport::closeTransport() {
    if (ssl != nullptr) {
        SSL_free(ssl);
        ssl = nullptr;
    }
    fd = -1;
    state = State::Closed;
    pendingOutput.clear();
    pendingOutputOffset = 0;
    inputBuffer.clear();
}
