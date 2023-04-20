
#include "tracer-connection-data.hpp"

DaemonAction PS::TracerConnectionData::handle_packet(const char* buffer)
{

    // The first character of the buffer is the event type.
    auto event_type = static_cast<TracerEventType>(buffer[0]);

    // Read the entire word from the buffer, but ignore it
    // because we already know what the event type is.

    while (*buffer != ' ' && *buffer != '\0')
        buffer++;

    switch (event_type) {
    case TRACER_EVENT_READ:
    case TRACER_EVENT_WRITE:
    case TRACER_EVENT_READ_WRITE:
    case TRACER_EVENT_UNLINK:
    case TRACER_EVENT_INODE_UNLINK:
        if (!m_tracer_event_handler.read_file_event(event_type, buffer)) {
            return DaemonAction::DISCONNECT;
        }
        return DaemonAction::CONTINUE;
    case TRACER_EVENT_CHILD:
        if (m_tracer_event_handler.read_child_event(buffer)) {
            return DaemonAction::ACKNOWLEDGE;
        }
        return DaemonAction::DISCONNECT;
    case TRACER_EVENT_DONE:
        mark_done();
        return DaemonAction::DISCONNECT;
    default:
        return DaemonAction::DISCONNECT;
    }
}
void PS::TracerConnectionData::make_process_attached(pid_t pid, PS::MakeConnectionData* make_data)
{
    m_tracer_event_handler.assign_make_process(pid, make_data);
}

bool PS::TracerConnectionData::has_child_with_pid(pid_t pid)
{
    auto& child_pids = m_tracer_event_handler.m_pid_database;
    return child_pids.find(pid) != child_pids.end();
}
