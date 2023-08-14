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

    void attach_to_tracer(TracerConnectionData* tracer);

    void turn_into_sibling();

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
