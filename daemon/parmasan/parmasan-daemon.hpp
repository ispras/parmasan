// SPDX-License-Identifier: MIT

#pragma once

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "daemon-connection-data.hpp"
#include "parmasan/inputs/parmasan-data-source.hpp"
#include "parmasan/inputs/socket/socket-server.hpp"
#include "tracer-process.hpp"

namespace PS
{

class ParmasanDaemon;

extern const char* ParmasanInteractiveModeDescr[];
enum class ParmasanInteractiveMode {
    NONE,
    SYNC
};

class ParmasanDaemonDelegate
{
  public:
    virtual void handle_race(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                             const PS::Race& race) = 0;
    virtual void handle_access(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                               const AccessRecord& access, const File& file) = 0;
};

class ParmasanDaemon : public ParmasanInputDelegate, public TracerProcessDelegate
{
  public:
    explicit ParmasanDaemon() = default;
    ParmasanDaemon(const ParmasanDaemon& copy) = delete;
    ParmasanDaemon(ParmasanDaemon&& move) = delete;
    ParmasanDaemon& operator=(const ParmasanDaemon& copy_assign) = delete;
    ParmasanDaemon& operator=(ParmasanDaemon&& move_assign) = delete;

    void set_interactive_mode(ParmasanInteractiveMode interactive_mode);
    ParmasanInteractiveMode get_interactive_mode();

    void set_delegate(ParmasanDaemonDelegate* delegate);

  private:
    void process_connected(ParmasanDataSource* input, pid_t pid) override;
    void process_message(ParmasanDataSource* input, pid_t pid, std::string_view message) override;
    void process_disconnected(ParmasanDataSource* input, pid_t pid) override;

    void protocol_error();

    void create_make_connection(pid_t pid);
    bool create_tracer_connection(pid_t pid);

    void delete_connection(pid_t pid);

    void handle_race(TracerProcess* tracer, const Race& race) override;
    void handle_access(TracerProcess* tracer, const PS::AccessRecord& access,
                       const PS::File& file) override;
    void handle_termination(TracerProcess* tracer) override;

    TracerProcess* m_tracer{};
    std::unordered_map<pid_t, std::unique_ptr<DaemonConnectionData>> m_connections{};
    DaemonAction action_for_message(pid_t fd, std::string_view message);

  private:
    ParmasanInteractiveMode m_interactive_mode = ParmasanInteractiveMode::NONE;
    ParmasanDaemonDelegate* m_delegate = nullptr;

    ParmasanDataSource* m_current_data_source = nullptr;
};

} // namespace PS
