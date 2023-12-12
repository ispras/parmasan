#pragma once

#include "daemon-connection-data.hpp"
#include "shared/structures.hpp"
#include "tracer-process.hpp"

namespace PS
{

class MakeConnectionHandler : public DaemonConnectionData
{
  public:
    explicit MakeConnectionHandler(pid_t pid)
        : DaemonConnectionData(), m_pid(pid)
    {
    }

    DaemonAction handle_packet(const char* buffer) override;

    void attach_to_tracer(TracerProcess* tracer);

    void turn_into_sibling();

    const MakeProcess& get_make_process()
    {
        return *m_make_process;
    }

  private:
    MakeProcess* m_make_process = nullptr;
    TracerProcess* m_attached_tracer = nullptr;

    int m_pid;
};

} // namespace PS
