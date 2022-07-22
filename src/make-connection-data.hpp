#pragma once

#include "daemon-connection-data.hpp"
#include "parmasan/race-search-engine.hpp"
#include "tracer-connection-data.hpp"

namespace PS {

class MakeConnectionData : public DaemonConnectionData {
  public:
    explicit MakeConnectionData(Connection<std::unique_ptr<DaemonConnectionData>>* connection)
        : DaemonConnectionData(connection) {}

    bool handle_packet(const char* buffer, size_t length) override;

    void handle_file_event(PS::TracerEventType event_type, TracerFileEvent* event,
                           const char* file_path);

    void attach_to_tracer(TracerConnectionData* tracer) { m_attached_tracer = tracer; }

  private:
    RaceSearchEngine m_race_search_engine;
    TracerConnectionData* m_attached_tracer = nullptr;
};

} // namespace PS