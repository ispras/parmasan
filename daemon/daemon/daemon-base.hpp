#pragma once

#include <iostream>
#include <vector>

enum class DaemonAction {
    CONTINUE,
    DISCONNECT,
    ACKNOWLEDGE,
    ERROR
};

class DaemonBase
{
  public:
    DaemonBase(const DaemonBase& copy) = delete;
    DaemonBase(DaemonBase&& move) = delete;
    explicit DaemonBase(int buffer_size = 1024)
    {
        m_buffer.resize(buffer_size);
    }
    ~DaemonBase();

    // MARK: handlers

    virtual DaemonAction handle_message()
    {
        return DaemonAction::ERROR;
    }

    // MARK: Unix socket life cycle

    // Creates a socketpair and returns the daemon input socket. Returns -1 on error.
    int setup();
    bool loop();
    void handle_connection_data();
    static bool setup_signal_blocking();
    static void reset_signal_blocking();

  private:
    // MARK: Utilities

    void handle_pending_signals();
    void send_acknowledgement_packet(int fd);
    bool setup_signal_fd();
    void cleanup_signal_fd();

  private:
    int m_sig_fd = -1;
    int m_read_fd = -1;
    int m_write_fd = -1;
    bool m_terminated = false;

  protected:
    std::vector<char> m_buffer{};
};
