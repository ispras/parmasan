
#include "socket-server.hpp"
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/signalfd.h>

int PS::SocketServer::setup()
{
    assert(m_server_socket == -1);

    m_server_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);

    if (m_server_socket == -1) {
        perror("socket failed");
        return false;
    }

    m_epoll_events.resize(MAX_EVENTS);
    m_epoll_fd = epoll_create1(0);
    if (add_fd_to_epoll_interest_list(m_server_socket) == -1) {
        close(m_server_socket);
        m_server_socket = -1;
        return -1;
    }

    setup_signal_fd();

    return 0;
}

int PS::SocketServer::add_fd_to_epoll_interest_list(int fd) const
{
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

    struct epoll_event event {
    };
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }

    return 0;
}

int PS::SocketServer::remove_fd_from_epoll_interest_list(int fd) const
{
    return epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
}

bool PS::SocketServer::setup_signal_blocking()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        perror("sigprocmask");
        return false;
    }

    return true;
}

void PS::SocketServer::reset_signal_blocking()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, nullptr);
}

bool PS::SocketServer::setup_signal_fd()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);

    m_sig_fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (m_sig_fd == -1) {
        perror("signalfd");
        return false;
    }

    if (add_fd_to_epoll_interest_list(m_sig_fd) == -1) {
        close(m_sig_fd);
        m_sig_fd = -1;
        return false;
    }

    return true;
}

void PS::SocketServer::cleanup_signal_fd()
{
    if (m_sig_fd >= -1) {
        remove_fd_from_epoll_interest_list(m_sig_fd);
        close(m_sig_fd);
        m_sig_fd = -1;
    }
}

static ssize_t get_packet_length(int fd)
{
    static char buffer = '\0';
    return recv(fd, &buffer, 0, MSG_TRUNC | MSG_PEEK);
}

void PS::SocketServer::handle_connection_data(int fd)
{
    while (true) {
        ssize_t packet_length = get_packet_length(fd);

        if (packet_length == 0) {
            break;
        } else if (packet_length > 0) {
            m_buffer.resize(packet_length);
            packet_length = recv(fd, m_buffer.data(), m_buffer.size(), 0);
            m_buffer.resize(packet_length);

            if (m_delegate) {
                m_delegate->handle_message(this, fd);
            }
        } else {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return;
            }
            perror("recv");
            break;
        }
    }

    remove_fd_from_epoll_interest_list(fd);

    if (m_delegate) {
        m_delegate->handle_disconnection(this, fd);
    }
}

bool PS::SocketServer::listen(std::string_view socket_name, int request_queue_length)
{
    size_t socket_length = socket_name.size();

    m_sockaddr.sun_family = AF_UNIX;

    if (socket_length >= sizeof(m_sockaddr.sun_path)) {
        socket_length = sizeof(m_sockaddr.sun_path) - 1;
    }

    memcpy(m_sockaddr.sun_path, socket_name.data(), socket_length);

    if (socket_name[0] == '$') {
        m_sockaddr.sun_path[0] = '\0';
    }

    int sockaddr_length = sizeof(m_sockaddr.sun_family) + socket_length;

    // Remove old socket file if it's not abstract
    if (m_sockaddr.sun_path[0] != '\0' && socket_length > 0) {
        unlink(m_sockaddr.sun_path);
    }

    if (bind(m_server_socket, reinterpret_cast<struct sockaddr*>(&m_sockaddr),
             sockaddr_length) < 0) {
        perror("bind failed");
        return false;
    }

    if (::listen(m_server_socket, request_queue_length) < 0) {
        perror("listen");
        return false;
    }

    return true;
}

int PS::SocketServer::wait_for_events()
{
    int events = epoll_wait(m_epoll_fd, m_epoll_events.data(), MAX_EVENTS, -1);

    if (events < 0) {
        perror("epoll_wait");
        if (errno == EINTR)
            return 0;
        return -1;
    }

    return events;
}

void PS::SocketServer::connect_new_client()
{
    int new_socket = -1;
    while ((new_socket = accept(m_server_socket, nullptr, nullptr)) >= 0) {
        if (add_fd_to_epoll_interest_list(new_socket) == 0) {
            if (m_delegate) {
                m_delegate->handle_connection(this, new_socket);
            }
        }
    }

    if (errno != EWOULDBLOCK && errno != EAGAIN) {
        perror("accept");
    }
}

bool PS::SocketServer::refresh_events()
{
    m_max_event_index = wait_for_events();
    return m_max_event_index > 0;
}

bool PS::SocketServer::loop()
{
    while (!m_terminated) {
        if (m_current_event_index == m_max_event_index) {
            m_current_event_index = 0;
            if (!refresh_events()) {
                m_terminated = true;
                return false;
            }
        }

        auto& event = m_epoll_events[m_current_event_index];

        int fd = event.data.fd;

        if (fd == m_server_socket) {
            connect_new_client();
            m_current_event_index++;
        } else if (fd == m_sig_fd) {
            handle_pending_signals();
            m_current_event_index++;
        } else {
            handle_connection_data(fd);
            m_current_event_index++;
        }
    }

    return true;
}

PS::SocketServer::~SocketServer()
{
    cleanup_signal_fd();
    unlink_socket();

    if (m_server_socket != -1) {
        close(m_server_socket);
        m_server_socket = -1;
    }
    if (m_epoll_fd != -1) {
        close(m_epoll_fd);
        m_epoll_fd = -1;
    }
}

void PS::SocketServer::unlink_socket()
{
    char* path = m_sockaddr.sun_path;

    if (path[0] == '\0')
        return;

    unlink(path);
}

void PS::SocketServer::handle_pending_signals()
{
    struct signalfd_siginfo fdsi {
    };
    ssize_t bytes = 0;

    while ((bytes = read(m_sig_fd, &fdsi, sizeof(fdsi))) == sizeof(fdsi)) {
        if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGCHLD || fdsi.ssi_signo == SIGINT) {
            fprintf(stderr, "Received signal %d (%s), terminating.\n", fdsi.ssi_signo,
                    strsignal(fdsi.ssi_signo));
            m_terminated = true;
            return;
        }
    }
    assert(bytes == -1 && (errno == EWOULDBLOCK || errno == EAGAIN));
}

void PS::SocketServer::set_delegate(SocketServerDelegate* delegate)
{
    m_delegate = delegate;
}

void PS::SocketServer::disconnect(int fd)
{
    close(fd);
}
