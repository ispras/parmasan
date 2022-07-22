#pragma once

#include "daemon-connection-data.hpp"
#include "daemon/connection.hpp"
#include "daemon/daemon-base.hpp"
#include "parmasan/race-search-engine.hpp"
#include "parmasan/tracer-event-handler.hpp"
#include "utils/buffer-reader.hpp"
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace PS {

class TracerConnectionData;

class ParmasanDaemon : public DaemonBase<std::unique_ptr<DaemonConnectionData>> {

    void handle_disconnection(DaemonConnection* connection) override;

    void handle_message(DaemonConnection* connection, size_t length) override;

    bool read_init_packet(DaemonConnection* connection, size_t length);

    TracerConnectionData* get_tracer_for_pid(pid_t pid);

    std::unordered_set<TracerConnectionData*> m_tracers{};
};

} // namespace PS