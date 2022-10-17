#pragma once

#include "entry.hpp"
#include <cassert>
#include <cstring>
#include <ios>
#include <string>

namespace PS {
enum TracerEventType : char {
    TRACER_EVENT_READ = 0,
    TRACER_EVENT_WRITE = 1,
    TRACER_EVENT_READ_WRITE = 2,
    TRACER_EVENT_UNLINK = 3,
    TRACER_EVENT_INODE_UNLINK = 4,
    TRACER_EVENT_CHILD = 5,
    TRACER_EVENT_DONE = 6
};

struct TracerChildEvent {
    pid_t pid;
    pid_t ppid;
};

struct TracerFileEvent {
    pid_t pid;
    Entry file_entry;
};

} // namespace PS