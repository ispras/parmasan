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
#include "tracer-process.hpp"

namespace PS
{

class ParmasanDaemon;

enum class ParmasanInteractiveMode {
    NONE,
    FAST,
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

class ParmasanDaemon : public DaemonBase, public TracerProcessDelegate
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
    void handle_message() override;

    void protocol_error();

    void create_make_connection(pid_t pid);

    void create_tracer_connection(pid_t pid);

    void delete_connection(pid_t pid);

    void send_ack_packet();
    void send_mode_packet();

    TracerProcess* get_tracer_for_pid(pid_t pid);

    void handle_race(TracerProcess* tracer, const Race& race) override;
    void handle_access(TracerProcess* tracer, const PS::AccessRecord& access,
                       const PS::File& file) override;

    std::unordered_set<DaemonConnectionData*> m_tracers{};
    std::unordered_map<pid_t, std::unique_ptr<DaemonConnectionData>> m_connections{};
    DaemonAction action_for_message();

  private:
    pid_t m_last_message_pid = 0;
    ParmasanInteractiveMode m_interactive_mode = ParmasanInteractiveMode::NONE;
    ParmasanDaemonDelegate* m_delegate = nullptr;
};

} // namespace PS
