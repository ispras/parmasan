#pragma once

#include "daemon-action.hpp"
#include "daemon-connection-data.hpp"
#include "parmasan/entry-history.hpp"
#include "parmasan/filename-database.hpp"
#include "parmasan/process.hpp"
#include "parmasan/race.hpp"
#include "parmasan/target-database.hpp"
#include "shared/structures.hpp"

namespace PS
{

class TracerProcessDelegate
{
  public:
    virtual void handle_race(TracerProcess* tracer, const PS::Race& race) = 0;
    virtual void handle_access(TracerProcess* tracer, const PS::AccessRecord& access,
                               const PS::File& file) = 0;
};

class TracerProcess : public DaemonConnectionData
{
  public:
    explicit TracerProcess(pid_t pid);

    DaemonAction handle_packet(const char* buffer) override;

    void assign_make_process(pid_t pid, MakeProcess* make_process);
    DaemonAction read_file_event(TracerEventType type, const char* buffer);
    DaemonAction read_child_event(const char* buffer);
    DaemonAction read_die_event(const char* buffer);

    PS::ProcessData* get_process(pid_t pid, unsigned int epoch);
    PS::ProcessData* get_alive_process(pid_t pid);
    unsigned int get_pid_epoch(pid_t pid);
    bool has_child_with_pid(pid_t pid);
    pid_t get_ppid(pid_t pid);
    BuildContext get_context_for_process(ProcessData* process);

    ProcessData* create_child(pid_t pid, ProcessData* parent);

    MakeProcess* create_make_process();

    void kill_process(ProcessData* process);

    const std::vector<std::unique_ptr<MakeProcess>>& get_make_processes();

    void set_delegate(TracerProcessDelegate* delegate);

    pid_t get_pid();

    void kill();

    void add_access_to_file(EntryData* entry_data, AccessRecord access);
    void check_required_dependencies(File* file, IDependencyFinder& dependency_finder);

    TracerProcessDelegate* m_delegate = nullptr;
    std::vector<std::unique_ptr<MakeProcess>> m_make_processes{};

    pid_t m_pid;
    std::unordered_map<pid_t, unsigned int> m_pid_epochs{};
    std::unordered_map<PidEpoch, std::unique_ptr<ProcessData>> m_pid_database{};
    FilenameDatabase m_filename_database{};
    bool m_killed = false;
};

} // namespace PS
