
#include "structures.hpp"

namespace PS
{

FileAccessType get_file_operation(TracerEventType event)
{
    switch (event) {
    case TRACER_EVENT_READ:
        return FileAccessType::read;
    case TRACER_EVENT_WRITE:
        return FileAccessType::write;
    case TRACER_EVENT_READ_WRITE:
        return FileAccessType::read_write;
    case TRACER_EVENT_UNLINK:
        return FileAccessType::unlink;
    case TRACER_EVENT_TOTAL_UNLINK:
        return FileAccessType::inode_unlink;
    default:
        assert(!"Invalid tracer event");
        std::abort();
    }
}
} // namespace PS
