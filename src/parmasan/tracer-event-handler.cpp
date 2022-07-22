
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
bool PS::TracerEventHandler::read_file_event(TracerEventType type, BufferReader& reader) {
    TracerFileEvent event{};
    if (!reader.read(&event)) {
        return false;
    }

    const char* file_path = reader.read_string();
    if (!file_path) {
        return false;
    }

    PS::MakeConnectionData* connection_data = get_make_process_for_pid(event.pid);

    if (!connection_data) {
        return true;
    }

    connection_data->handle_file_event(type, &event, file_path);

    return true;
}

bool PS::TracerEventHandler::read_child_event(BufferReader& reader) {
    TracerChildEvent event{};
    if (!reader.read(&event)) {
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
