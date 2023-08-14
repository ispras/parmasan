
#include "tracer-connection-data.hpp"
#include "make-connection-data.hpp"
#include "shared/structures.hpp"

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
        return read_file_event(event_type, buffer);
    case TRACER_EVENT_CHILD:
        return read_child_event(buffer);
    case TRACER_EVENT_DIE:
        return read_die_event(buffer);
    default:
        return DaemonActionCode::ERROR;
    }
}

PS::MakeConnectionData* PS::TracerConnectionData::get_make_process_for_pid(pid_t pid)
{
    while (auto pid_data = get_pid_data(pid)) {
        if (pid_data->make_process) {
            return pid_data->make_process;
        }
        pid = pid_data->ppid;
    }
    return nullptr;
}
DaemonAction PS::TracerConnectionData::read_file_event(TracerEventType type, const char* buffer)
{

    // Read length of the path
    size_t length = 0;
    int res = 0;
    if (sscanf(buffer, "%zu %n", &length, &res) != 1) {
        return DaemonActionCode::ERROR;
    }
    buffer += res;

    // Read the file path
    std::string file_path(buffer, length);
    buffer += length;

    TracerFileEvent event{};

    if (sscanf(buffer, "%d %lu %lu %d %n", &event.pid, &event.file_entry.device,
               &event.file_entry.inode, &event.return_code, &res) != 4) {
        return DaemonActionCode::ERROR;
    }

    PS::MakeConnectionData* connection_data = get_make_process_for_pid(event.pid);

    if (!connection_data) {
        return DaemonActionCode::CONTINUE;
    }

    connection_data->handle_file_event(type, &event, file_path);

    return DaemonActionCode::CONTINUE;
}

DaemonAction PS::TracerConnectionData::read_child_event(const char* buffer)
{
    pid_t pid = 0;
    pid_t ppid = 0;

    if (sscanf(buffer, "%d %d", &pid, &ppid) != 2) {
        return DaemonActionCode::ERROR;
    }

    m_pid_database[pid].ppid = ppid;

    return DaemonActionCode::ACKNOWLEDGE;
}

DaemonAction PS::TracerConnectionData::read_die_event(const char* buffer)
{
    pid_t pid = 0;

    if (sscanf(buffer, "%d", &pid) != 1) {
        return DaemonActionCode::ERROR;
    }

    return DaemonAction::disconnect(pid);
}

void PS::TracerConnectionData::assign_make_process(pid_t pid, PS::MakeConnectionData* make_process)
{
    m_pid_database[pid].make_process = make_process;
}

const PS::PIDData* PS::TracerConnectionData::get_pid_data(pid_t pid)
{
    auto it = m_pid_database.find(pid);
    if (it == m_pid_database.end())
        return nullptr;
    return &it->second;
}

bool PS::TracerConnectionData::has_child_with_pid(pid_t pid)
{
    auto& child_pids = m_pid_database;
    return child_pids.find(pid) != child_pids.end();
}

pid_t PS::TracerConnectionData::get_ppid(pid_t pid)
{
    auto data = get_pid_data(pid);
    if (!data) {
        return 0;
    }
    return data->ppid;
}
