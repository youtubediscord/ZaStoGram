/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2015-2018.
 */

#ifndef PROXYCHECKINFO_H
#define PROXYCHECKINFO_H

#include <stdint.h>
#include <sstream>
#include "Defines.h"

#ifdef ANDROID
#include <jni.h>
#endif

enum class ProxyCheckState : uint8_t {
    Queued,
    Connecting,
    PingSent,
    Finished,
};

class ProxyCheckInfo {

public:
    ~ProxyCheckInfo();

    ProxyCheckState state = ProxyCheckState::Queued;
    int32_t connectionNum = 0;
    int32_t requestToken = 0;
    uint32_t connectionToken = 0;
    int64_t startedAtMillis = 0;
    bool finished = false;
    std::string address;
    uint16_t port = 1080;
    std::string username;
    std::string password;
    std::string secret;
    int32_t mtProxyTlsProfile = 0;
    int32_t mtProxyClientHelloFragmentation = 0;
    int64_t pingId = 0;
    onRequestTimeFunc onRequestTime;
    int32_t instanceNum = 0;

#ifdef ANDROID
    jobject ptr1 = nullptr;
#endif
};


#endif
