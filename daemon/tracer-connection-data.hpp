#pragma once

#include "daemon-connection-data.hpp"

namespace PS
{

class ParmasanDaemon;

class TracerConnectionData : public DaemonConnectionData
{
  public:
    explicit TracerConnectionData(int m_fd, std::ostream& dump_output_stream)
        : DaemonConnectionData(m_fd), m_race_search_engine(dump_output_stream)
    {
    }

    DaemonAction handle_packet(const char* buffer) override;

    void make_process_attached(pid_t pid, MakeConnectionData* make_data);

    bool has_child_with_pid(pid_t pid);

    pid_t get_ppid(pid_t pid)
    {
        auto data = get_pid_data(pid);
        if (!data) {
            return 0;
        }
        return data->ppid;
    }

    const PIDData* get_pid_data(pid_t pid)
    {
        auto it = m_tracer_event_handler.m_pid_database.find(pid);
        if (it == m_tracer_event_handler.m_pid_database.end())
            return nullptr;
        return &it->second;
    }

    RaceSearchEngine& get_race_search_engine()
    {
        return m_race_search_engine;
    }

  private:
    TracerEventHandler m_tracer_event_handler{};
    RaceSearchEngine m_race_search_engine;
};

} // namespace PS
