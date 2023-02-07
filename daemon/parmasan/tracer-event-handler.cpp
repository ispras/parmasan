
#include "tracer-event-handler.hpp"
#include "make-connection-data.hpp"
#include "parmasan-daemon.hpp"
#include "race-search-engine.hpp"

PS::MakeConnectionData* PS::TracerEventHandler::get_make_process_for_pid(pid_t pid) {
    while (pid > 0) {
        auto pid_data = m_pid_database[pid];
        if (pid_data.make_process) {
            return pid_data.make_process;
        }
        pid = pid_data.ppid;
    }
    return nullptr;
}
bool PS::TracerEventHandler::read_file_event(TracerEventType type, const char* buffer) {

    // Read length of the path
    size_t length = 0;
    int res = 0;
    if(sscanf(buffer, "%zu %n", &length, &res) <= 0) {
        return false;
    }
    buffer += res;

    // Read the file path
    std::string file_path(buffer, length);
    buffer += length;

    TracerFileEvent event {};

    if(sscanf(buffer, "%d %lu %lu %n", &event.pid, &event.file_entry.device, &event.file_entry.inode, &res) <= 0) {
        return false;
    }

    PS::MakeConnectionData* connection_data = get_make_process_for_pid(event.pid);

    if (!connection_data) {
        return true;
    }

    connection_data->handle_file_event(type, &event, file_path);

    return true;
}

bool PS::TracerEventHandler::read_child_event(const char* buffer) {
    TracerChildEvent event{};

    if(sscanf(buffer, "%d %d", &event.pid, &event.ppid) < 0) {
        return false;
    }

    register_child(event.ppid, event.pid);

    return true;
}
void PS::TracerEventHandler::register_child(pid_t ppid, pid_t pid) {
    auto& pid_data = m_pid_database[pid];
    pid_data.ppid = ppid;
}
void PS::TracerEventHandler::assign_make_process(pid_t pid, PS::MakeConnectionData* make_process) {
    m_pid_database[pid].make_process = make_process;
}
