#pragma once

#include "daemon/daemon-base.hpp"
#include "parmasan/race-search-engine.hpp"
#include "parmasan/tracer-event-handler.hpp"

namespace PS
{

class DaemonConnectionData
{
  public:
    int m_fd;
    bool m_done_flag = false;

    DaemonConnectionData(const DaemonConnectionData& copy) = delete;
    DaemonConnectionData(DaemonConnectionData&& move) = delete;
    explicit DaemonConnectionData(int m_fd)
        : m_fd(m_fd) {}
    virtual ~DaemonConnectionData() = default;

    virtual DaemonAction handle_packet(const char* /*buffer*/)
    {
        return DaemonAction::CONTINUE;
    }

    bool mark_done();
    void send_acknowledgement_packet() const;
};

} // namespace PS
