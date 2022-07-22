
#include "tracer-connection-data.hpp"

bool PS::TracerConnectionData::handle_packet(const char* buffer, size_t length) {
    BufferReader reader(buffer, length);

    TracerEventType event_type;
    if (!reader.read(&event_type))
        return false;

    switch (event_type) {
    case TRACER_EVENT_READ:
    case TRACER_EVENT_WRITE:
    case TRACER_EVENT_READ_WRITE:
    case TRACER_EVENT_UNLINK:
    case TRACER_EVENT_INODE_RELEASE:
        return m_tracer_event_handler.read_file_event(event_type, reader);
    case TRACER_EVENT_CHILD:
        if (m_tracer_event_handler.read_child_event(reader)) {
            send_acknowledgement_packet();
            return true;
        }
        return false;
    case TRACER_EVENT_DONE:
        return mark_done();
    default:
        return false;
    }
}
void PS::TracerConnectionData::make_process_attached(pid_t pid, PS::MakeConnectionData* make_data) {
    m_tracer_event_handler.assign_make_process(pid, make_data);
}

bool PS::TracerConnectionData::has_child_with_pid(pid_t pid) {
    auto& child_pids = m_tracer_event_handler.m_pid_database;
    return child_pids.find(pid) != child_pids.end();
}
