#pragma once

#include <fstream>
#include <iostream>
#include <unordered_map>
#include "shared/structures.hpp"

namespace PS
{

class MakeConnectionData;

struct PIDData {
    pid_t ppid;
    MakeConnectionData* make_process;
};

class RaceSearchEngine;
class TracerEventHandler
{
  public:
    explicit TracerEventHandler() = default;

    PS::MakeConnectionData* get_make_process_for_pid(pid_t pid);

    void register_child(pid_t ppid, pid_t pid);
    void assign_make_process(pid_t pid, MakeConnectionData* make_process);
    bool read_file_event(TracerEventType type, const char* buffer);
    bool read_child_event(const char* buffer);

    std::unordered_map<pid_t, PIDData> m_pid_database{};
};

} // namespace PS
