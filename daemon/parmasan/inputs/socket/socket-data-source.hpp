#pragma once

#include <unordered_map>
#include "../../../../parmasan/parmasan-daemon.hpp"
#include "../parmasan-data-source.hpp"
#include "socket-server.hpp"

namespace PS
{

class ParmasanSocketDataSource : public ParmasanDataSource, public SocketServerDelegate
{
  public:
    ParmasanSocketDataSource() = default;
    ParmasanSocketDataSource(const ParmasanSocketDataSource& copy) = delete;
    ParmasanSocketDataSource(ParmasanSocketDataSource&& move) noexcept
    {
        *this = std::move(move);
    }

    ParmasanSocketDataSource& operator=(const ParmasanSocketDataSource& copy) = delete;
    ParmasanSocketDataSource& operator=(ParmasanSocketDataSource&& move) noexcept
    {
        m_pid_map = std::move(move.m_pid_map);
        m_fd_map = std::move(move.m_fd_map);
        m_server = std::move(move.m_server);

        // Move the delegate pointer to the new position
        m_server.set_delegate(this);
        return *this;
    };
    virtual ~ParmasanSocketDataSource() = default;

    bool listen(const std::string& sockaddr, int request_queue_length);

    bool loop() override;
    void set_build_args(int argc, char** argv);
    void set_interactive_mode(PS::ParmasanInteractiveMode mode);

    void disconnect_process(pid_t m_pid) override;

  private:
    void handle_connection(SocketServer* server, int fd) override;

    void handle_disconnection(SocketServer* server, int fd) override;

    void handle_message(SocketServer* server, int fd) override;

    SocketServer m_server;
    std::unordered_map<int, pid_t> m_pid_map;
    std::unordered_map<pid_t, int> m_fd_map;

    std::string m_sockaddr;
    PS::ParmasanInteractiveMode m_interactive_mode;

    int m_build_argc = 0;
    char** m_build_argv = nullptr;
};

} // namespace PS
