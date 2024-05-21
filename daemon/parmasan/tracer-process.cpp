
#include "tracer-process.hpp"
#include <csignal>
#include "make-connection-handler.hpp"
#include "parmasan/make-process.hpp"
#include "shared/structures.hpp"

PS::TracerProcess::TracerProcess(pid_t pid)
    : DaemonConnectionData(), m_pid(pid)
{
    auto self_process = std::make_unique<ProcessData>();
    self_process->id.pid = pid;
    self_process->id.epoch = 0;
    self_process->cmd_line = "tracer";

    m_pid_epochs[m_pid] = 0;
    m_pid_database[{m_pid, 0}] = std::move(self_process);
}

DaemonAction PS::TracerProcess::handle_packet(const char* buffer)
{
    if (m_killed) {
        return DaemonActionCode::DISCONNECT;
    }

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
    case TRACER_EVENT_TOTAL_UNLINK:
        return read_file_event(event_type, buffer);
    case TRACER_EVENT_CHILD:
        return read_child_event(buffer);
    case TRACER_EVENT_DIE:
        return read_die_event(buffer);
    default:
        return DaemonActionCode::ERROR;
    }
}

DaemonAction PS::TracerProcess::read_file_event(TracerEventType type, const char* buffer)
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

    Entry file_entry{};
    int return_code = 0;
    pid_t pid = 0;

    if (sscanf(buffer, "%d %lu %lu %d %n", &pid, &file_entry.device,
               &file_entry.inode, &return_code, &res) != 4) {
        return DaemonActionCode::ERROR;
    }

    if (file_entry.inode == 0) {
        return DaemonActionCode::CONTINUE;
    }

    auto process = get_alive_process(pid);

    EntryData* entry_data = m_filename_database.update_file(file_path, file_entry);

    if (!entry_data) {
        return DaemonActionCode::CONTINUE;
    }

    BuildContext context = get_context_for_process(process);

    if (!context) {
        return DaemonActionCode::CONTINUE;
    }

    AccessRecord record{
        .access_type = get_file_operation(type),
        .context = context,
        .process = process,
        .return_code = return_code};

    add_access_to_file(entry_data, record);

    return DaemonActionCode::CONTINUE;
}

void PS::TracerProcess::add_access_to_file(EntryData* entry_data, AccessRecord access)
{

    if (m_delegate) {
        m_delegate->handle_access(this, access, *entry_data->last_known_file);
    }

    // Report the access both to the entry-bound and path-bound dependency finder.
    // After update_file call, last_known_file field stores the reference to the
    // file at file_path, so it can be used right away.

    auto last_known_file = entry_data->last_known_file;

    entry_data->dependency_finder.push_access(access);
    check_required_dependencies(last_known_file, entry_data->dependency_finder);

    last_known_file->m_path_bound_dependency_finder.push_access(access);
    check_required_dependencies(last_known_file, last_known_file->m_path_bound_dependency_finder);

    last_known_file->m_dir_lookup_dependency_finder.push_access(access);
    check_required_dependencies(last_known_file, last_known_file->m_dir_lookup_dependency_finder);

    // If there is a parent directory, make sure to add a 'dir_lookup' access record
    // to it as well.

    auto parent = last_known_file->m_parent;

    if (parent) {
        access.access_type = FileAccessType::dir_lookup;
        if (m_delegate) {
            m_delegate->handle_access(this, access, *parent);
        }

        parent->m_dir_lookup_dependency_finder.push_access(access);
        check_required_dependencies(parent, parent->m_dir_lookup_dependency_finder);
    }
}

void PS::TracerProcess::check_required_dependencies(File* file,
                                                    IDependencyFinder& dependency_finder)
{
    do {
        if (!m_delegate) {
            continue;
        }

        if (dependency_finder.is_required_dependency()) {
            Race race{
                .file = file,
                .left_access = dependency_finder.get_left_access(),
                .right_access = dependency_finder.get_right_access(),
            };
            m_delegate->handle_race(this, race);
        }
    } while (dependency_finder.next());
}

PS::BuildContext PS::TracerProcess::get_context_for_process(PS::ProcessData* process)
{
    PS::MakeProcess* make_process = process->get_make_process();

    if (!make_process) {
        return {};
    }

    BuildContext context = {
        .target = make_process->get_target_for_process(process),
        .goal = make_process->get_current_goal()};

    // If the make process itself have accessed a file, it won't get associated
    // with any target of this make process. In this case this access should be
    // linked with the context this make process was invoked with.
    if (!context) {
        return make_process->get_parent_context();
    }

    return context;
}

DaemonAction PS::TracerProcess::read_child_event(const char* buffer)
{
    pid_t pid = 0;
    pid_t ppid = 0;

    int cmdline_length = 0;
    int cmdline_offset;
    const char* cmdline = nullptr;

    if (sscanf(buffer, "%d %d %d %n", &pid, &ppid, &cmdline_length, &cmdline_offset) != 3) {
        return DaemonActionCode::ERROR;
    }

    cmdline = buffer + cmdline_offset;

    auto parent = get_alive_process(ppid);

    if (!parent) {
        return DaemonActionCode::ERROR;
    }

    auto process = create_child(pid, parent);

    process->cmd_line = std::string(cmdline, cmdline_length);

    return DaemonActionCode::CONTINUE;
}

DaemonAction PS::TracerProcess::read_die_event(const char* buffer)
{
    pid_t pid = 0;

    if (sscanf(buffer, "%d", &pid) != 1) {
        return DaemonActionCode::ERROR;
    }

    auto process = get_alive_process(pid);

    if (process) {
        kill_process(process);
        return DaemonAction::disconnect(pid);
    } else {
        return DaemonActionCode::ERROR;
    }
}

void PS::TracerProcess::assign_make_process(pid_t pid, PS::MakeProcess* make_process)
{
    auto process = get_alive_process(pid);
    assert(process != nullptr);

    if (process->make_process) {
        // Make a sibling of the existing make process
        kill_process(process);
        process = create_child(pid, process->parent);
    }

    make_process->set_process_data(process);
    process->make_process = make_process;
}

PS::ProcessData* PS::TracerProcess::get_process(pid_t pid, unsigned int epoch)
{
    PidEpoch key{.pid = pid, .epoch = epoch};
    auto it = m_pid_database.find(key);
    if (it == m_pid_database.end())
        return nullptr;

    return it->second.get();
}

PS::ProcessData* PS::TracerProcess::get_alive_process(pid_t pid)
{
    auto it = m_pid_epochs.find(pid);
    if (it == m_pid_epochs.end())
        return nullptr;

    return get_process(pid, it->second);
}

unsigned int PS::TracerProcess::get_pid_epoch(pid_t pid)
{
    auto it = m_pid_epochs.find(pid);
    if (it == m_pid_epochs.end())
        return 0;
    return it->second;
}

bool PS::TracerProcess::has_child_with_pid(pid_t pid)
{
    return get_alive_process(pid) != nullptr;
}

pid_t PS::TracerProcess::get_ppid(pid_t pid)
{
    auto data = get_alive_process(pid);
    if (!data || !data->parent) {
        return 0;
    }
    return data->parent->id.pid;
}

PS::ProcessData* PS::TracerProcess::create_child(pid_t pid, ProcessData* parent)
{
    // When the process performs an 'exec' syscall, the sanitizer receives
    // a repeated 'child' message. In this case, the process should not be
    // created from scratch, rather the old one should be updated.

    auto existing_process = get_alive_process(pid);
    if (existing_process) {
        return existing_process;
    }

    unsigned int epoch = m_pid_epochs[pid];

    auto process = std::make_unique<ProcessData>();
    process->parent = parent;
    process->id.pid = pid;
    process->id.epoch = epoch;

    process->next_sibling = parent->first_child;
    parent->first_child = process.get();

    ProcessData* process_ptr = process.get();

    m_pid_database[PidEpoch{.pid = pid, .epoch = epoch}] = std::move(process);

    return process_ptr;
}

PS::MakeProcess* PS::TracerProcess::create_make_process()
{
    m_make_processes.push_back(std::make_unique<MakeProcess>(this));
    return m_make_processes.back().get();
}

void PS::TracerProcess::set_delegate(PS::TracerProcessDelegate* delegate)
{
    m_delegate = delegate;
}

pid_t PS::TracerProcess::get_pid()
{
    return m_pid;
}

void PS::TracerProcess::kill()
{
    if (!m_killed) {
        m_killed = true;
        if (m_delegate) {
            m_delegate->handle_termination(this);
        }
    }
}

const std::vector<std::unique_ptr<PS::MakeProcess>>& PS::TracerProcess::get_make_processes()
{
    return m_make_processes;
}

void PS::TracerProcess::kill_process(PS::ProcessData* process)
{
    if (!process->dead) {
        process->dead = true;
        // Move the epoch so get_process(pid_t) return nullptr from now on
        ++m_pid_epochs[process->id.pid];
    }
}
