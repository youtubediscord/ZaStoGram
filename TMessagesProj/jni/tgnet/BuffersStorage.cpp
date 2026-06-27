/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 *
 * Copyright Nikolai Kudashov, 2015-2018.
 */

#include "BuffersStorage.h"
#include "FileLog.h"
#include "NativeByteBuffer.h"

#include <time.h>

namespace {
const int64_t BUFFER_POOL_PRESSURE_LOG_INTERVAL_MS = 1000;

uint32_t bufferPoolMaxCountForCapacity(uint32_t capacity) {
    if (capacity == 8 || capacity == 128 || capacity == 1024 + 200) {
        return 80;
    }
    return 10;
}

int64_t bufferPoolMonotonicMillis() {
    struct timespec timeSpec;
    clock_gettime(CLOCK_MONOTONIC, &timeSpec);
    return (int64_t) timeSpec.tv_sec * 1000 + timeSpec.tv_nsec / 1000000;
}
}

BuffersStorage &BuffersStorage::getInstance() {
    static BuffersStorage instance(true);
    return instance;
}

BuffersStorage::BuffersStorage(bool threadSafe) {
    isThreadSafe = threadSafe;
    if (isThreadSafe) {
        pthread_mutex_init(&mutex, NULL);
    }
    for (uint32_t a = 0; a < 4; a++) {
        freeBuffers8.push_back(new NativeByteBuffer((uint32_t) 8));
    }
    for (uint32_t a = 0; a < 5; a++) {
        freeBuffers128.push_back(new NativeByteBuffer((uint32_t) 128));
    }
}

NativeByteBuffer *BuffersStorage::getFreeBuffer(uint32_t size) {
    uint32_t byteCount = 0;
    std::vector<NativeByteBuffer *> *arrayToGetFrom = nullptr;
    NativeByteBuffer *buffer = nullptr;
    if (size <= 8) {
        arrayToGetFrom = &freeBuffers8;
        byteCount = 8;
    } else if (size <= 128) {
        arrayToGetFrom = &freeBuffers128;
        byteCount = 128;
    } else if (size <= 1024 + 200) {
        arrayToGetFrom = &freeBuffers1024;
        byteCount = 1024 + 200;
    } else if (size <= 4096 + 200) {
        arrayToGetFrom = &freeBuffers4096;
        byteCount = 4096 + 200;
    } else if (size <= 16384 + 200) {
        arrayToGetFrom = &freeBuffers16384;
        byteCount = 16384 + 200;
    } else if (size <= 40000) {
        arrayToGetFrom = &freeBuffers32768;
        byteCount = 40000;
    } else if (size <= 160000) {
        arrayToGetFrom = &freeBuffersBig;
        byteCount = 160000;
    } else {
        buffer = new NativeByteBuffer(size);
    }

    if (arrayToGetFrom != nullptr) {
        if (isThreadSafe) {
            pthread_mutex_lock(&mutex);
        }
        if (arrayToGetFrom->size() > 0) {
            buffer = (*arrayToGetFrom)[0];
            arrayToGetFrom->erase(arrayToGetFrom->begin());
        }
        if (isThreadSafe) {
            pthread_mutex_unlock(&mutex);
        }
        if (buffer == nullptr) {
            buffer = new NativeByteBuffer(byteCount);
            if (LOGS_ENABLED) DEBUG_D("create new %u buffer", byteCount);
        }
    }
    if (buffer != nullptr) {
        buffer->limit(size);
        buffer->rewind();
    }
    return buffer;
}

void BuffersStorage::reuseFreeBuffer(NativeByteBuffer *buffer) {
    if (buffer == nullptr) {
        return;
    }
    std::vector<NativeByteBuffer *> *arrayToReuse = nullptr;
    uint32_t capacity = buffer->capacity();
    uint32_t maxCount = bufferPoolMaxCountForCapacity(capacity);
    if (capacity == 8) {
        arrayToReuse = &freeBuffers8;
    } else if (capacity == 128) {
        arrayToReuse = &freeBuffers128;
    } else if (capacity == 1024 + 200) {
        arrayToReuse = &freeBuffers1024;
    } else if (capacity == 4096 + 200) {
        arrayToReuse = &freeBuffers4096;
    } else if (capacity == 16384 + 200) {
        arrayToReuse = &freeBuffers16384;
    } else if (capacity == 40000) {
        arrayToReuse = &freeBuffers32768;
    } else if (capacity == 160000) {
        arrayToReuse = &freeBuffersBig;
    }
    if (arrayToReuse != nullptr) {
        if (isThreadSafe) {
            pthread_mutex_lock(&mutex);
        }
        if (arrayToReuse->size() < maxCount) {
            arrayToReuse->push_back(buffer);
        } else {
            if (LOGS_ENABLED) {
                int64_t now = bufferPoolMonotonicMillis();
                int64_t lastLogTime = lastPressureLogByCapacity[capacity];
                if (lastLogTime == 0 || now - lastLogTime >= BUFFER_POOL_PRESSURE_LOG_INTERVAL_MS) {
                    lastPressureLogByCapacity[capacity] = now;
                    DEBUG_D("buffer_pool_pressure capacity=%u cached=%u limit=%u", capacity, (uint32_t) arrayToReuse->size(), maxCount);
                }
            }
            delete buffer;
        }
        if (isThreadSafe) {
            pthread_mutex_unlock(&mutex);
        }
    } else {
        delete buffer;
    }
}
