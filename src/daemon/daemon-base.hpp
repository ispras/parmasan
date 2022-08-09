#pragma once

#include "connection.hpp"
#include <cassert>
#include <cerrno>
#include <iostream>
#include <memory>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

template <typename ConnectionData> class DaemonBase {
    static constexpr int MAX_EVENTS = 128;

  public:
    typedef Connection<ConnectionData> DaemonConnection;

    DaemonBase(const DaemonBase& copy) = delete;
    DaemonBase(DaemonBase&& move) = delete;
    explicit DaemonBase(int buffer_size = 1024) { m_buffer.resize(buffer_size); }
    ~DaemonBase();

    // MARK: handlers

    virtual void handle_connection(DaemonConnection* /*connection*/) {}
    virtual void handle_disconnection(DaemonConnection* /*connection*/) {}
    virtual void handle_message(DaemonConnection* /*connection*/, size_t /*length*/) {}

    // MARK: Unix socket life cycle

    bool create_socket();
    bool listen(const char* socket_name, int request_queue_length = 4096);
    void loop();
    void handle_connection_data(DaemonConnection* connection);

  private:
    // MARK: Utilities

    void connect_new_client();
    int mark_socket_for_listening(int fd);
    int wait_for_events();
    int stop_listening_socket(DaemonConnection* connection);

  private:
    int m_epoll_fd = 0;
    int m_server_socket = 0;
    std::vector<struct epoll_event> m_epoll_events{};

  protected:
    std::unordered_map<int, std::unique_ptr<DaemonConnection>> m_connections{};
    std::vector<char> m_buffer{};
};

template <typename ConnectionData> bool DaemonBase<ConnectionData>::create_socket() {
    assert(!m_server_socket);

    m_server_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);

    if (m_server_socket == -1) {
        perror("socket failed");
        return false;
    }

    m_epoll_events.resize(MAX_EVENTS);
    m_epoll_fd = epoll_create1(0);
    if (mark_socket_for_listening(m_server_socket) == -1) {
        close(m_server_socket);
        return false;
    }

    return true;
}

template <typename ConnectionData>
bool DaemonBase<ConnectionData>::listen(const char* socket_name, int request_queue_length) {
    assert(socket_name);
    size_t socket_length = 0;
    if (socket_name[0] == '\0') {
        socket_length = strlen(socket_name + 1) + 1;
    } else {
        socket_length = strlen(socket_name);
    }

    struct sockaddr_un server_address {};
    server_address.sun_family = AF_UNIX;

    if (socket_length >= sizeof(server_address.sun_path)) {
        socket_length = sizeof(server_address.sun_path) - 1;
    }

    // Remove old socket file if it's not abstract
    if (socket_name[0] == '\0' && socket_length > 0) {
        unlink(socket_name);
    }

    memcpy(server_address.sun_path, socket_name, socket_length);

    if (bind(m_server_socket, (struct sockaddr*)&server_address,
             sizeof(server_address.sun_family) + socket_length) < 0) {
        perror("bind failed");
        return false;
    }

    if (::listen(m_server_socket, request_queue_length) < 0) {
        perror("listen");
        return false;
    }

    return true;
}

template <typename ConnectionData>
void DaemonBase<ConnectionData>::handle_connection_data(DaemonConnection* connection) {
    while (connection->is_open()) {

        ssize_t packet_length = connection->get_packet_length();

        if (packet_length > 0) {
            if ((size_t)packet_length > m_buffer.size())
                m_buffer.resize(packet_length);

            packet_length = connection->receive(m_buffer.data(), m_buffer.size());
        }

        if (packet_length > 0) {
            handle_message(connection, packet_length);
        } else {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return;
            }
            perror("recv");
            connection->close();
        }

        if (!connection->is_open()) {
            stop_listening_socket(connection);
            handle_disconnection(connection);
        }
    }
}

template <typename ConnectionData>
int DaemonBase<ConnectionData>::stop_listening_socket(DaemonConnection* connection) {
    return epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, connection->descriptor, nullptr);
}

template <typename ConnectionData> void DaemonBase<ConnectionData>::loop() {
    int events = 0;

    while ((events = wait_for_events()) >= 0) {

        for (int i = 0; i < events; i++) {
            int fd = m_epoll_events[i].data.fd;

            if (fd == m_server_socket) {
                connect_new_client();
            } else {
                auto it = m_connections.find(fd);
                if (it == m_connections.end())
                    continue;
                DaemonConnection* connection = it->second.get();

                handle_connection_data(connection);
            }
        }
    }
}

template <typename ConnectionData> void DaemonBase<ConnectionData>::connect_new_client() {
    int new_socket = -1;
    while ((new_socket = accept(m_server_socket, nullptr, nullptr)) >= 0) {
        auto it = m_connections.emplace(new_socket, std::make_unique<DaemonConnection>(new_socket));
        DaemonConnection* connection = it.first->second.get();
        if (mark_socket_for_listening(new_socket) == 0) {
            handle_connection(connection);
        }
    }

    if (errno != EWOULDBLOCK && errno != EAGAIN) {
        perror("accept");
    }
}

template <typename ConnectionData> int DaemonBase<ConnectionData>::wait_for_events() {

    int events = epoll_wait(m_epoll_fd, m_epoll_events.data(), MAX_EVENTS, -1);

    if (events < 0) {
        perror("epoll_wait");
        if (errno == EINTR)
            return 0;
        return -1;
    }

    return events;
}
template <typename ConnectionData> DaemonBase<ConnectionData>::~DaemonBase() {
    if (m_server_socket) {
        close(m_server_socket);
        m_server_socket = 0;
    }
    if (m_epoll_fd) {
        close(m_epoll_fd);
        m_epoll_fd = 0;
    }
}

template <typename ConnectionData>
int DaemonBase<ConnectionData>::mark_socket_for_listening(int fd) {

    // Make socket non-blocking

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl");
        return -1;
    }

    // Add socket to epoll

    struct epoll_event event {};
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }

    return 0;
}
