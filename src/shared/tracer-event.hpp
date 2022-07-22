#pragma once

#include "parmasan/entry.hpp"
#include "parmasan/file-access-type.hpp"
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
    TRACER_EVENT_INODE_RELEASE = 4,
    TRACER_EVENT_CHILD = 5,
    TRACER_EVENT_DONE = 6
};

bool is_file_operation(TracerEventType event);
FileAccessType get_file_operation(TracerEventType event);

struct TracerChildEvent {
    pid_t pid;
    pid_t ppid;
};

struct TracerFileEvent {
    pid_t pid;
    Entry file_entry;
};

} // namespace PS