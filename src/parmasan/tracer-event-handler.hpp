#pragma once

#include "entry.hpp"
#include "file.hpp"
#include "shared/tracer-event.hpp"
#include "utils/buffer-reader.hpp"
#include <fstream>
#include <iostream>
#include <unordered_map>

namespace PS {

struct MakeConnectionData;

struct PIDData {
    pid_t ppid;
    MakeConnectionData* make_process;
};

class RaceSearchEngine;
class TracerEventHandler {
  public:
    explicit TracerEventHandler() = default;

    PS::MakeConnectionData* get_make_process_for_pid(pid_t pid);

    void register_child(pid_t ppid, pid_t pid);
    void assign_make_process(pid_t pid, MakeConnectionData* make_process);
    bool read_file_event(TracerEventType type, BufferReader& reader);
    bool read_child_event(BufferReader& reader);

    std::unordered_map<pid_t, PIDData> m_pid_database{};
};

} // namespace PS