#pragma once

#include "daemon-connection-data.hpp"
#include "parmasan/race-search-engine.hpp"
#include "tracer-connection-data.hpp"

namespace PS
{

class MakeConnectionData : public DaemonConnectionData
{
  public:
    explicit MakeConnectionData(int fd, pid_t pid)
        : DaemonConnectionData(fd), m_pid(pid)
    {
    }

    DaemonAction handle_packet(const char* buffer) override;

    void handle_file_event(PS::TracerEventType event_type, TracerFileEvent* event,
                           const std::string& file_path);

    void attach_to_tracer(TracerConnectionData* tracer)
    {
        m_attached_tracer = tracer;
        reset();
    }

    void reset()
    {
        m_target_database = m_attached_tracer->get_race_search_engine().create_target_database();

        // If this make process is a sub-make, find the parent target

        MakeConnectionData* parent_make = nullptr;
        pid_t pid = m_attached_tracer->get_ppid(m_pid);
        while (pid != 0) {
            auto data = m_attached_tracer->get_pid_data(pid);
            if (data->make_process) {
                parent_make = data->make_process;
                break;
            }
            pid = data->ppid;
        }

        if (!parent_make) {
            // This is a top-level make
            return;
        }

        m_target_database->set_parent_target(parent_make->get_target_database().get_target(m_pid));
    }

    const TargetDatabase& get_target_database()
    {
        return *m_target_database;
    }

  private:
    TargetDatabase* m_target_database = nullptr;
    TracerConnectionData* m_attached_tracer = nullptr;

    int m_pid;
};

} // namespace PS
