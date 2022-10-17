#pragma once

#include <cassert>
#include <cerrno>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

class DaemonClient {

  public:
    DaemonClient(DaemonClient&& move) = delete;
    DaemonClient(const DaemonClient& copy) = delete;
    DaemonClient() = default;
    ~DaemonClient() {
        if (!m_closed)
            close();
    }

    bool setup_socket() {
        assert(!m_client_socket);
        m_client_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (m_client_socket < 0) {
            perror("socket");
            return false;
        }
        return true;
    }

    bool connect(const char* socket_name) {
        assert(socket_name);
        m_server_address.sun_family = AF_UNIX;

        size_t socket_length = 0;
        if (socket_name[0] == '\0') {
            socket_length = strlen(socket_name + 1) + 1;
        } else {
            socket_length = strlen(socket_name);
        }

        if (socket_length == 0) {
            socket_length = strlen(socket_name);
        }

        if (socket_length >= sizeof(m_server_address.sun_path)) {
            socket_length = sizeof(m_server_address.sun_path) - 1;
        }

        memcpy(m_server_address.sun_path, socket_name, socket_length);

        int connection_result =
            ::connect(m_client_socket, reinterpret_cast<struct sockaddr*>(&m_server_address),
                      sizeof(m_server_address.sun_family) + socket_length);
        if (connection_result < 0) {
            perror("connect");
            return false;
        }

        return true;
    }

    ssize_t send(void* ptr, size_t length, int flags = 0) {
        assert(!m_closed);
        return ::send(m_client_socket, ptr, length, flags);
    }

    ssize_t read(void* ptr, size_t length) {
        assert(!m_closed);
        return ::read(m_client_socket, ptr, length);
    }

    void close() {
        m_closed = true;
        ::close(m_client_socket);
    }

    bool is_open() { return m_client_socket > 0 && !m_closed; }

  private:
    int m_client_socket = 0;
    struct sockaddr_un m_server_address {};
    bool m_closed = false;
};