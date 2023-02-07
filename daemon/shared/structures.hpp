#pragma once

#include "parmasan/entry.hpp"
#include "parmasan/file-access-type.hpp"
#include <cassert>
#include <cstring>
#include <ios>
#include <string>

namespace PS {

enum GeneralEventType : char {
    GENERAL_EVENT_INIT = 'I',
};

enum TracerEventType : char {
    TRACER_EVENT_READ = 'R',
    TRACER_EVENT_WRITE = 'W',
    TRACER_EVENT_READ_WRITE = 'A',
    TRACER_EVENT_UNLINK = 'U',
    TRACER_EVENT_INODE_UNLINK = 'I',
    TRACER_EVENT_CHILD = 'C',
    TRACER_EVENT_DONE = 'F'
};

enum MakeEventType : char {
    MAKE_EVENT_TARGET_PID = 'T',
    MAKE_EVENT_DEPENDENCY = 'D',
    MAKE_EVENT_DONE = 'F'
};

enum MessageAuthorType : char {
    MESSAGE_TYPE_TRACER = 'T',
    MESSAGE_TYPE_MAKE = 'M',
};

struct TracerChildEvent {
    pid_t pid;
    pid_t ppid;
};

struct TracerFileEvent {
    pid_t pid;
    Entry file_entry;
};

FileAccessType get_file_operation(TracerEventType event);

} // namespace PS