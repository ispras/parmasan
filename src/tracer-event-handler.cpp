
#include "tracer-event-handler.hpp"
#include "engine.hpp"
#include "tracer-event.hpp"

PS::Target* PS::TracerEventHandler::get_target_for_pid(pid_t pid) {
    Target* target = nullptr;
    while (target == nullptr) {
        auto pid_data = pid_database[pid];
        target = m_engine->m_target_database.get_target_for(pid, pid_data.instance);
        pid = pid_data.ppid;
        if (pid == 0)
            break;
    }
    return target;
}
void PS::TracerEventHandler::read(std::ifstream&& stream) {
    TracerEventType event;
    std::string path;

    while (stream >> event) {
        if (is_file_operation(event)) {
            int pid = 0;
            Entry entry{};

            stream >> pid >> entry;

            stream >> path;
            File* file = m_engine->m_filename_database.update_file(path, entry);

            if (!file)
                continue;

            Target* target = get_target_for_pid(pid);
            if (!target)
                continue;

            FileAccessRecord record{.m_access_type = get_file_operation(event), .m_target = target};

            file->m_accesses.push_back(record);
        } else if (event == TracerEventType::child) {
            int pid = 0, ppid = 0;
            stream >> ppid >> pid;
            auto& pid_data = pid_database[pid];
            pid_data.instance++;
            pid_data.ppid = ppid;
        }
    }
}
