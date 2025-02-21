// SPDX-License-Identifier: MIT

#include "socket-data-source.hpp"
#include <filesystem>
#include <sys/socket.h>
#include <unistd.h>
#include "utils/run-shell.hpp"

bool PS::ParmasanSocketDataSource::listen(const std::string& sockaddr, int request_queue_length)
{
    if (m_server.setup() < 0)
        return false;
    m_server.set_delegate(this);

    if (sockaddr[0] == '$') {
        m_sockaddr = sockaddr;
    } else {
        m_sockaddr = (std::filesystem::current_path() /= sockaddr).string();
    }

    return m_server.listen(sockaddr, request_queue_length);
}

bool PS::ParmasanSocketDataSource::loop()
{
    PS::SocketServer::setup_signal_blocking();

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // PARMASAN_DAEMON_SOCK tells the child processes where is the daemon socket located
        setenv("PARMASAN_DAEMON_SOCK", m_sockaddr.c_str(), 1);

        // PARMASAN_SYNC_MODE tells how often should the synchronisation occur
        setenv("PARMASAN_SYNC_MODE",
               PS::ParmasanInteractiveModeDescr[(int)m_interactive_mode], 1);

        setpgrp();

        PS::SocketServer::reset_signal_blocking();
        run_shell(m_build_argc, m_build_argv);
    }

    bool result = m_server.loop();

    if (m_fd_map.count(child_pid)) {
        kill(-child_pid, SIGKILL);
    }

    return result;
}

void PS::ParmasanSocketDataSource::disconnect_process(pid_t m_pid)
{
    if (m_fd_map.count(m_pid)) {
        int fd = m_fd_map.at(m_pid);
        m_pid_map.erase(fd);
        m_fd_map.erase(m_pid);

        m_server.disconnect(fd);
    }
}

void PS::ParmasanSocketDataSource::handle_connection(PS::SocketServer* /* server */, int fd)
{
    pid_t process_pid = -1;
    socklen_t len = sizeof(pid_t);
    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &process_pid, &len);

    m_pid_map.insert({fd, process_pid});
    m_fd_map.insert({process_pid, fd});
    m_delegate->process_connected(this, process_pid);
}

void PS::ParmasanSocketDataSource::handle_disconnection(PS::SocketServer* /* server */, int fd)
{
    auto it = m_pid_map.find(fd);
    if (it == m_pid_map.end())
        return;

    auto pid = it->second;
    m_delegate->process_disconnected(this, pid);
    m_pid_map.erase(fd);
    m_fd_map.erase(pid);
}

void PS::ParmasanSocketDataSource::handle_message(PS::SocketServer* server, int fd)
{
    std::string_view message = server->get_buffer();
    bool is_sync = false;

    if (message.rfind("SYNC ", 0) == 0) {
        is_sync = true;
    } else if (message.rfind("ASYNC", 0) == 0) {
        is_sync = false;
    } else {
        return;
    }

    message = message.substr(6);

    auto it = m_pid_map.find(fd);
    if (it != m_pid_map.end()) {
        auto pid = it->second;
        m_delegate->process_message(this, pid, message);
    }

    if (is_sync) {
        char packet[] = "ACK";
        send(fd, packet, sizeof(packet), 0);
    }
}

void PS::ParmasanSocketDataSource::set_build_args(int argc, char** argv)
{
    m_build_argc = argc;
    m_build_argv = argv;
}

void PS::ParmasanSocketDataSource::set_interactive_mode(PS::ParmasanInteractiveMode mode)
{
    m_interactive_mode = mode;
}

void PS::ParmasanSocketDataSource::close()
{
    m_server.close();
}
