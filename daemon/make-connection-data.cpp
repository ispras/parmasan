
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
        if (m_target_database->read_dependency_event(buffer)) {
            return DaemonActionCode::CONTINUE;
        }
        return DaemonActionCode::ERROR;
    case MAKE_EVENT_TARGET_PID:
        if (m_target_database->read_target_pid_event(buffer)) {
            return DaemonActionCode::ACKNOWLEDGE;
        }
        return DaemonActionCode::ERROR;
    case GENERAL_EVENT_INIT:
        // As it turned out, GNU make (and remake) have its own way
        // of handling makefile updates. When a makefile is updated,
        // the make process just re-executes itself without any kind
        // of shutdown. This means that the init event can be received
        // multiple times from the seemingly same process. The best way
        // of interpreting this is to pretend that the new make process
        // is a sub-make process. The only problem is - it's hard to know
        // what exact target have caused the make to re-execute. However,
        // it's impossible to have a race between two epochs of the same
        // makefile. Re-exec is a strong barrier. It's guaranteed that
        // there is nothing else running as a make child when it happens.
        // Thus, it should be fine to consider re-executed make as a
        // sibling, not a child. The parmasan will still be able to find
        // race conditions between re-executed make and its own parent
        // make processes.
        turn_into_sibling();

        return DaemonActionCode::ACKNOWLEDGE;
    default:
        return DaemonActionCode::ERROR;
    }
}
void PS::MakeConnectionData::handle_file_event(PS::TracerEventType event_type,
                                               TracerFileEvent* event,
                                               const std::string& file_path)
{
    if (!m_attached_tracer) {
        return;
    }

    if (event->return_code < 0) {
        return;
    }

    if (event->file_entry.inode == 0) {
        return;
    }

    auto& engine = m_attached_tracer->get_race_search_engine();

    EntryData* entry_data = engine.m_filename_database.update_file(file_path, event->file_entry);

    if (!entry_data) {
        return;
    }

    Target* target = nullptr;
    pid_t target_pid = event->pid;

    while (!target && target_pid) {
        target = m_target_database->get_target(target_pid);
        target_pid = m_attached_tracer->get_ppid(target_pid);
    }

    if (!target) {
        return;
    }

    AccessRecord record{.access_type = get_file_operation(event_type), .target = target};

    // Report the access both to the entry-bound and path-bound dependency finder.
    // After update_file call, last_known_file field stores the reference to the
    // file at file_path, so it can be used right away.

    entry_data->dependency_finder.push_access(record);
    engine.check_required_dependencies(
        entry_data->last_known_file,
        entry_data->dependency_finder);

    entry_data->last_known_file->m_dependency_finder.push_access(record);
    engine.check_required_dependencies(
        entry_data->last_known_file,
        entry_data->last_known_file->m_dependency_finder);
}

void PS::MakeConnectionData::turn_into_sibling()
{
    // Turn ourselves into a sub-make of our parent.
    auto old_target_database = m_target_database;
    m_target_database = m_attached_tracer->get_race_search_engine().create_target_database();

    if (old_target_database) {
        m_target_database->set_parent_target(old_target_database->get_parent_target());
    }
}

void PS::MakeConnectionData::attach_to_tracer(PS::TracerConnectionData* tracer)
{
    m_attached_tracer = tracer;
    m_target_database = m_attached_tracer->get_race_search_engine().create_target_database();

    // If this make process is a sub-make, find the parent target

    pid_t ppid = m_attached_tracer->get_ppid(m_pid);
    PS::MakeConnectionData* parent_make = m_attached_tracer->get_make_process_for_pid(ppid);

    if (!parent_make) {
        // This is a top-level make
        return;
    }

    m_target_database->set_parent_target(parent_make->get_target_database().get_target(m_pid));
}
