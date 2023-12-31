
#include "daemon-base.hpp"
#include <cassert>
#include <cerrno>
#include <csignal>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/signalfd.h>

static int move_fd_above(int fd, int limit)
{
    if (fd > limit || fd < 0) {
        return fd;
    }

    int result = move_fd_above(dup(fd), limit);
    close(fd);

    return result;
}

int DaemonBase::setup()
{
    int fds[2] = {};

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) < 0) {
        cleanup_signal_fd();
        return -1;
    }

    m_read_fd = fds[0];
    m_write_fd = fds[1];

    // Sometimes GNU configure (and other shell scripts) can override
    // file descriptors without checking whether it was already taken.
    // Shell scripts can only use single-digit file descriptors, so
    // here the exposed file descriptor is moved above 9 to avoid
    // some possible collisions
    m_write_fd = move_fd_above(m_write_fd, 9);

    // We don't want fds[0] to be blocking the daemon from reading the signal fd, so make it
    // non-blocking
    int flags = fcntl(m_read_fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(m_read_fd, F_SETFL, flags);

    return m_write_fd;
}

bool DaemonBase::setup_signal_blocking()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        perror("sigprocmask");
        return false;
    }

    return true;
}

bool DaemonBase::setup_signal_fd()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);

    m_sig_fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (m_sig_fd == -1) {
        perror("signalfd");
        return false;
    }

    return true;
}

void DaemonBase::handle_connection_data()
{
    while (true) {
        char buffer = '\0';
        ssize_t packet_length = recv(m_read_fd, &buffer, 0, MSG_TRUNC | MSG_PEEK);

        if (packet_length > 0) {
            if (static_cast<size_t>(packet_length + 1) > m_buffer.size())
                m_buffer.resize(packet_length + 1);

            packet_length = recv(m_read_fd, m_buffer.data(), m_buffer.size(), 0);
        }

        if (packet_length > 0) {
            m_buffer[packet_length] = '\0';
            handle_message();
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            perror("recv");
        }
    }
}

bool DaemonBase::loop()
{
    if (!setup_signal_fd()) {
        return false;
    }

    fd_set read_fds{};

    while (!m_terminated) {

        // Wait for a message from m_read_fd or a signal from m_sig_fd
        // with use of select syscall

        FD_ZERO(&read_fds);
        FD_SET(m_read_fd, &read_fds);
        FD_SET(m_sig_fd, &read_fds);

        int max_fd = std::max(m_read_fd, m_sig_fd);
        int result = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);

        if (result < 0) {
            perror("select");
            return false;
        }

        if (FD_ISSET(m_read_fd, &read_fds)) {
            handle_connection_data();
        }

        if (FD_ISSET(m_sig_fd, &read_fds)) {
            handle_pending_signals();
        }
    }

    cleanup_signal_fd();

    return true;
}

DaemonBase::~DaemonBase()
{
    if (m_read_fd >= 0) {
        close(m_read_fd);
        m_read_fd = -1;
    }

    if (m_write_fd >= 0) {
        close(m_write_fd);
        m_write_fd = -1;
    }
}

void DaemonBase::handle_pending_signals()
{
    struct signalfd_siginfo fdsi {
    };
    ssize_t bytes = 0;

    while ((bytes = read(m_sig_fd, &fdsi, sizeof(fdsi))) == sizeof(fdsi)) {
        if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGCHLD) {
            printf("Received signal %d (%s), terminating.\n", fdsi.ssi_signo,
                   strsignal(fdsi.ssi_signo));
            m_terminated = true;
        }
    }
    assert(bytes == -1 && (errno == EWOULDBLOCK || errno == EAGAIN));
}

void DaemonBase::reset_signal_blocking()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, nullptr);
}

void DaemonBase::cleanup_signal_fd()
{
    if (m_sig_fd >= -1) {
        close(m_sig_fd);
        m_sig_fd = -1;
    }
}
