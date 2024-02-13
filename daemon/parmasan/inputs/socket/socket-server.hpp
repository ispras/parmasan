#pragma once

#include <cstdint>
#include <iostream>
#include <vector>
#include <sys/un.h>
#include <sys/epoll.h>

namespace PS
{

class SocketServer;

class SocketServerDelegate
{
  public:
    virtual void handle_connection(SocketServer* server, int /* fd */) = 0;
    virtual void handle_disconnection(SocketServer* server, int /* fd */) = 0;
    virtual void handle_message(SocketServer* server, int /* fd */) = 0;
};

class SocketServer
{
  public:
    SocketServer(const SocketServer& copy) = delete;
    SocketServer(SocketServer&& move) = default;
    explicit SocketServer(int buffer_size = 1024)
    {
        m_buffer.resize(buffer_size);
    }
    SocketServer& operator=(SocketServer&& move) = default;

    ~SocketServer();

    // MARK: handlers

    // MARK: Unix socket life cycle
    int setup();
    bool loop();
    bool listen(std::string_view socket_name, int request_queue_length);

    static bool setup_signal_blocking();
    static void reset_signal_blocking();

    void set_delegate(SocketServerDelegate* delegate);
    void disconnect(int fd);

    const std::string& get_buffer()
    {
        return m_buffer;
    }

  private:
    // MARK: Utilities

    int remove_fd_from_epoll_interest_list(int fd) const;
    int add_fd_to_epoll_interest_list(int fd) const;

    int wait_for_events();
    bool refresh_events();

    void connect_new_client();
    void handle_connection_data(int fd);

    void handle_pending_signals();
    bool setup_signal_fd();
    void cleanup_signal_fd();
    void unlink_socket();

    static constexpr int MAX_EVENTS = 128;

  protected:
    int m_sig_fd = -1;
    int m_max_event_index = 0;
    int m_current_event_index = 0;
    int m_epoll_fd = -1;
    int m_server_socket = -1;
    bool m_terminated = false;

    struct sockaddr_un m_sockaddr {
    };
    std::vector<epoll_event> m_epoll_events{};
    std::string m_buffer{};

    SocketServerDelegate* m_delegate = nullptr;
};

} // namespace PS
