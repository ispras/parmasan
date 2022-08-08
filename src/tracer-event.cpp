
#include "tracer-event.hpp"

namespace PS {

bool is_file_operation(TracerEventType event) {
    return event == TracerEventType::read || event == TracerEventType::write ||
           event == TracerEventType::read_write || event == TracerEventType::unlink;
}

FileAccessType get_file_operation(TracerEventType event) {
    switch(event) {
    case TracerEventType::read: return FileAccessType::read;
    case TracerEventType::write: return FileAccessType::write;
    case TracerEventType::read_write: return FileAccessType::read_write;
    case TracerEventType::unlink: return FileAccessType::unlink;
    default: assert(!"Invalid tracer event");
    }
    return FileAccessType::read;
}
}
