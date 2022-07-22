
#include "tracer-event.hpp"

namespace PS {

bool is_file_operation(TracerEventType event) {
    return event == TRACER_EVENT_READ || event == TRACER_EVENT_WRITE ||
           event == TRACER_EVENT_READ_WRITE || event == TRACER_EVENT_UNLINK;
}

FileAccessType get_file_operation(TracerEventType event) {
    switch (event) {
    case TRACER_EVENT_READ:
        return FileAccessType::read;
    case TRACER_EVENT_WRITE:
        return FileAccessType::write;
    case TRACER_EVENT_READ_WRITE:
        return FileAccessType::read_write;
    case TRACER_EVENT_UNLINK:
        return FileAccessType::unlink;
    case TRACER_EVENT_INODE_RELEASE:
        return FileAccessType::inode_release;
    default:
        assert(!"Invalid tracer event");
        std::abort();
    }
}
} // namespace PS
