
#include "make-connection-data.hpp"
#include "shared/make-event-type.hpp"

bool PS::MakeConnectionData::handle_packet(const char* buffer, size_t length) {
    BufferReader reader(buffer, length);

    MakeEventType event_type;
    if (!reader.read(&event_type))
        return false;

    switch (event_type) {
    case MAKE_EVENT_DEPENDENCY:
        return m_race_search_engine.m_target_database.read_dependency_event(reader);
    case MAKE_EVENT_TARGET_PID:
        if (m_race_search_engine.m_target_database.read_target_pid_event(reader)) {
            send_acknowledgement_packet();
            return true;
        }
        return false;
    case MAKE_EVENT_DONE:
        if (!mark_done()) {
            return false;
        }
        m_race_search_engine.search_for_races();
        return true;
    default:
        return false;
    }
}
void PS::MakeConnectionData::handle_file_event(PS::TracerEventType event_type,
                                               TracerFileEvent* event, const char* file_path) {
    EntryData* entry_data =
        m_race_search_engine.m_filename_database.update_file(file_path, event->file_entry);

    if (!entry_data) {
        return;
    }

    Target* target = nullptr;
    pid_t target_pid = event->pid;

    while (!target && target_pid) {
        target = m_race_search_engine.m_target_database.get_target(target_pid);
        target_pid = m_attached_tracer->get_ppid(target_pid);
    }

    if (!target) {
        return;
    }

    AccessRecord record{.access_type = get_file_operation(event_type), .target = target};

    entry_data->accesses.push_back(record);

    // After update_file call, last_known_file field stores the reference to the
    // file at file_path.
    entry_data->last_known_file->m_accesses.push_back(record);
}
