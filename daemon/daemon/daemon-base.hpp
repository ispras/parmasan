#pragma once

#include <cstdint>
#include <iostream>
#include <vector>

enum class DaemonActionCode : uint32_t {
    CONTINUE,
    DISCONNECT,
    ACKNOWLEDGE,
    ACKNOWLEDGE_IF_SYNC,
    ERROR
};

struct DaemonAction {
    DaemonActionCode action;

    // For now, the payload is actually an optional pid that
    // is used only for DaemonActionCode::DISCONNECT and
    // DaemonActionCode::ERROR messages.
    union {
        // Pid of the process that should be disconnected.
        // PID = 0 refers to the message author process.
        pid_t pid;
    } payload{};

    DaemonAction(DaemonActionCode action)
        : action(action) {}

    static DaemonAction disconnect(pid_t pid)
    {
        DaemonAction action{DaemonActionCode::DISCONNECT};
        action.payload.pid = pid;
        return action;
    }
}; // namespace DaemonAction

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

    virtual void handle_message() {}

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
    bool setup_signal_fd();
    void cleanup_signal_fd();

  protected:
    int m_sig_fd = -1;
    int m_read_fd = -1;
    int m_write_fd = -1;
    bool m_terminated = false;

    std::vector<char> m_buffer{};
};
