
#include "tracer-event-handler.hpp"
#include "make-connection-data.hpp"
#include "parmasan-daemon.hpp"
#include "race-search-engine.hpp"

PS::MakeConnectionData* PS::TracerEventHandler::get_make_process_for_pid(pid_t pid)
{
    while (pid > 0) {
        auto pid_data = m_pid_database[pid];
        if (pid_data.make_process) {
            return pid_data.make_process;
        }
        pid = pid_data.ppid;
    }
    return nullptr;
}
DaemonAction PS::TracerEventHandler::read_file_event(TracerEventType type, const char* buffer)
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

DaemonAction PS::TracerEventHandler::read_child_event(const char* buffer)
{
    pid_t pid = 0;
    pid_t ppid = 0;

    if (sscanf(buffer, "%d %d", &pid, &ppid) != 2) {
        return DaemonActionCode::ERROR;
    }

    m_pid_database[pid].ppid = ppid;

    return DaemonActionCode::ACKNOWLEDGE;
}

DaemonAction PS::TracerEventHandler::read_die_event(const char* buffer)
{
    pid_t pid = 0;

    if (sscanf(buffer, "%d", &pid) != 1) {
        return DaemonActionCode::ERROR;
    }

    return DaemonAction::disconnect(pid);
}

void PS::TracerEventHandler::assign_make_process(pid_t pid, PS::MakeConnectionData* make_process)
{
    m_pid_database[pid].make_process = make_process;
}
