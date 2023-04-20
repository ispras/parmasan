#pragma once

#include "daemon-connection-data.hpp"
#include "parmasan/race-search-engine.hpp"
#include "tracer-connection-data.hpp"

namespace PS
{

class MakeConnectionData : public DaemonConnectionData
{
  public:
    explicit MakeConnectionData(int m_fd, std::ostream& dump_output_stream)
        : DaemonConnectionData(m_fd), m_race_search_engine(dump_output_stream)
    {
    }

    DaemonAction handle_packet(const char* buffer) override;

    void handle_file_event(PS::TracerEventType event_type, TracerFileEvent* event,
                           const std::string& file_path);

    void attach_to_tracer(TracerConnectionData* tracer)
    {
        m_attached_tracer = tracer;
    }

  private:
    RaceSearchEngine m_race_search_engine;
    TracerConnectionData* m_attached_tracer = nullptr;
};

} // namespace PS
