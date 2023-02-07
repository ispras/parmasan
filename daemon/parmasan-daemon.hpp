#pragma once

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "daemon-connection-data.hpp"
#include "daemon/daemon-base.hpp"
#include "parmasan/race-search-engine.hpp"
#include "parmasan/tracer-event-handler.hpp"

namespace PS {

class TracerConnectionData;

class ParmasanDaemon : public DaemonBase {

  public:
    explicit ParmasanDaemon(std::ostream& dump_output_stream): m_dump_output(dump_output_stream) {};
    ParmasanDaemon(const ParmasanDaemon& copy) = delete;
    ParmasanDaemon(ParmasanDaemon&& move) = delete;
    ParmasanDaemon& operator=(const ParmasanDaemon& copy_assign) = delete;
    ParmasanDaemon& operator=(ParmasanDaemon&& move_assign) = delete;

  private:
    DaemonAction handle_message() override;

    void protocol_error();

    void create_make_connection(pid_t pid);

    void create_tracer_connection(pid_t pid);

    TracerConnectionData* get_tracer_for_pid(pid_t pid);

    std::unordered_set<TracerConnectionData*> m_tracers{};
    std::unordered_map<pid_t, std::unique_ptr<DaemonConnectionData>> m_connections{};
    DaemonAction action_for_message();

  private:
    std::ostream& m_dump_output;
    pid_t m_last_message_pid = 0;
};

} // namespace PS