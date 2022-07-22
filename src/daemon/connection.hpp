#pragma once

#include <cassert>
#include <functional>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

template <typename ConnectionData> struct Connection {
    int descriptor = 0;
    bool closed = false;
    ConnectionData data{};

    Connection(const Connection& copy) = delete;
    Connection(Connection&& move) noexcept = default;
    explicit Connection(int descriptor) : descriptor(descriptor), closed(false), data() {}

    bool is_open() const { return !closed; }

    void close() {
        ::close(descriptor);
        closed = true;
    }

    ssize_t receive(void* ptr, size_t length, int flags = 0) {
        assert(!closed);
        return ::recv(descriptor, ptr, length, flags);
    }

    ssize_t send(void* ptr, size_t length, int flags = 0) {
        assert(!closed);
        return ::send(descriptor, ptr, length, flags);
    }

    ssize_t get_packet_length() {
        static char buffer = '\0';
        return receive(&buffer, 0, MSG_TRUNC | MSG_PEEK);
    }
};

namespace std {

template <typename ConnectionData> struct hash<Connection<ConnectionData>> {
    std::size_t operator()(const Connection<ConnectionData>& key) const {
        return std::hash<int>()(key.descriptor);
    }
};
} // namespace std