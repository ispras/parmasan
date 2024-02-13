#pragma once

#include <csignal>
#include <cstdint>

enum class DaemonActionCode : uint32_t {
    CONTINUE,
    DISCONNECT,
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
