#pragma once

#include "daemon/daemon-base.hpp"
#include "parmasan/race-search-engine.hpp"

namespace PS
{

class DaemonConnectionData
{
  public:
    DaemonConnectionData(const DaemonConnectionData& copy) = delete;
    DaemonConnectionData(DaemonConnectionData&& move) = delete;
    explicit DaemonConnectionData() = default;
    virtual ~DaemonConnectionData() = default;

    virtual DaemonAction handle_packet(const char* /*buffer*/)
    {
        return DaemonActionCode::CONTINUE;
    }
};

} // namespace PS
