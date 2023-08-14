#pragma once

#include "daemon-connection-data.hpp"
#include "shared/structures.hpp"

namespace PS
{

class MakeConnectionData;

struct PIDData {
    pid_t ppid;
    MakeConnectionData* make_process;
};

class TracerConnectionData : public DaemonConnectionData
{
  public:
    explicit TracerConnectionData(int m_fd, std::ostream& dump_output_stream)
        : DaemonConnectionData(m_fd), m_race_search_engine(dump_output_stream)
    {
    }

    DaemonAction handle_packet(const char* buffer) override;

    RaceSearchEngine& get_race_search_engine()
    {
        return m_race_search_engine;
    }

    PS::MakeConnectionData* get_make_process_for_pid(pid_t pid);

    void assign_make_process(pid_t pid, MakeConnectionData* make_process);
    DaemonAction read_file_event(TracerEventType type, const char* buffer);
    DaemonAction read_child_event(const char* buffer);
    DaemonAction read_die_event(const char* buffer);

    const PS::PIDData* get_pid_data(pid_t pid);
    bool has_child_with_pid(pid_t pid);
    pid_t get_ppid(pid_t pid);

  private:
    RaceSearchEngine m_race_search_engine;

    std::unordered_map<pid_t, PIDData> m_pid_database{};
};

} // namespace PS
