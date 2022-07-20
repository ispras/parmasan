#pragma once

#include "seccomp.hpp"
#include "tracee.hpp"
#include "entry.hpp"
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <string>

class tracer {
  public:
    tracer(std::string result_file_path) : m_result_file_path(result_file_path) {}
    ~tracer() = default;
    tracer(const tracer& copy) = delete;
    tracer& operator=(const tracer& copy_assign) = delete;
    tracer(tracer&& move) = delete;
    tracer& operator=(tracer& move_assign) = delete;

    void trace(char* argv[]);

    void report_read(pid_t pid, struct stat* file);
    void report_write(pid_t pid, struct stat* file);
    void report_read_write(pid_t pid, struct stat* file);
    void report_child(pid_t parent, pid_t child);
    void report_unlink(pid_t pid, const std::string& path, struct stat* stat);

    bool is_bpf_enabled();

    static constexpr int GENERAL_PTRACE_FLAGS = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                                                PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                                                PTRACE_O_TRACEEXEC;

  private:
    /* MARK: Private methods */

    void parent_task();
    void bpf_loop();
    void ptrace_loop();

    void child_task(char* argv[]);

    void setup_seccomp();

    /* MARK: Syscall and fork handlers */

    void report_read_write_for_flags(tracee* process, int fd, int flags);
    void handle_open_syscall(tracee* process, const char* pathname, int flags, mode_t mode);
    void handle_openat_syscall(tracee* process, int dirfd, const char* pathname, int flags,
                               mode_t mode);
    void handle_openat2_syscall(tracee* process, int dirfd, const char* pathname,
                                struct open_how* how, size_t size);
    void handle_creat_syscall(tracee* process, const char* pathname, mode_t mode);
    void handle_unlink_syscall(tracee* process, const char* pathname);
    void handle_unlinkat_syscall(tracee* process, int dirfd, const char *path, int flag);
    void handle_syscall(tracee* process);

    void handle_fork_clone(tracee* process);
    void handle_possible_child(tracee* process);

    /* MARK: Utilities */

    tracee* get_process(pid_t pid);
    tracee* wait_for_process();
    void unlink_path(pid_t pid, const std::string& path);

    /* MARK: Private fields */

    std::string m_result_file_path;
    FILE* m_result_file = nullptr;
    pid_t m_child_pid = -1;
    bool m_bpf_enabled = true;
    std::unordered_map<pid_t, tracee> processes{};
    std::unordered_map<FileNode, int> ino_instances{};
};
