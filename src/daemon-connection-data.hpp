#pragma once

#include "daemon/daemon-base.hpp"
#include "parmasan/race-search-engine.hpp"
#include "parmasan/tracer-event-handler.hpp"
#include "shared/connection-state.hpp"

namespace PS {

class DaemonConnectionData {
  public:
    ConnectionState m_state = CONNECTION_STATE_UNINITIALIZED;
    Connection<std::unique_ptr<DaemonConnectionData>>* m_connection{};

    bool m_done_flag = false;

    DaemonConnectionData(const DaemonConnectionData& copy) = delete;
    DaemonConnectionData(DaemonConnectionData&& move) = delete;
    explicit DaemonConnectionData(Connection<std::unique_ptr<DaemonConnectionData>>* connection)
        : m_connection(connection) {}
    virtual ~DaemonConnectionData() = default;

    virtual bool handle_packet(const char* /*buffer*/, size_t /*length*/) { return true; }

    bool mark_done();
    void send_acknowledgement_packet() const;
};

} // namespace PS