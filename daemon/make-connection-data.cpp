
#include "make-connection-data.hpp"

DaemonAction PS::MakeConnectionData::handle_packet(const char* buffer)
{

    // Get the first character of the buffer, which is the event type.
    auto event_type = buffer[0];

    // Read the entire word from the buffer, but ignore it
    // because we already know what the event type is.

    while (*buffer != ' ' && *buffer != '\0')
        buffer++;

    switch (event_type) {
    case MAKE_EVENT_DEPENDENCY:
        if (m_race_search_engine.m_target_database.read_dependency_event(buffer)) {
            return DaemonAction::CONTINUE;
        }
        return DaemonAction::ERROR;
    case MAKE_EVENT_TARGET_PID:
        if (m_race_search_engine.m_target_database.read_target_pid_event(buffer)) {
            return DaemonAction::ACKNOWLEDGE;
        }
        return DaemonAction::ERROR;
    case GENERAL_EVENT_INIT:
        // As it turned out, GNU make (and remake) have its own way
        // of handling makefile updates. When a makefile is updated,
        // the make process just re-executes itself without any kind
        // of shutdown. This means that the init event can be received
        // multiple times from the seemingly same process. The best way
        // of interpreting this is to pretend that old make process have
        // sent MAKE_EVENT_DONE, and new make process have sent
        // GENERAL_EVENT_INIT. Thus, in a case of repeated init event,
        // search for races and reset the connection state.
        m_race_search_engine.search_for_races();
        m_race_search_engine.reset();

        return DaemonAction::ACKNOWLEDGE;
    case MAKE_EVENT_DONE:
        if (mark_done()) {
            m_race_search_engine.search_for_races();
            return DaemonAction::DISCONNECT;
        }
        return DaemonAction::ERROR;
    default:
        return DaemonAction::ERROR;
    }
}
void PS::MakeConnectionData::handle_file_event(PS::TracerEventType event_type,
                                               TracerFileEvent* event,
                                               const std::string& file_path)
{
    if (event->return_code < 0) {
        return;
    }

    if (event->file_entry.inode == 0) {
        return;
    }

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
