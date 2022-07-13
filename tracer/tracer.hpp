#pragma once

#include "seccomp.hpp"
#include "tracee.hpp"
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <unordered_map>

struct tracee_file;

class tracer {
  public:
    tracer(FILE* result_file) : m_result_file(result_file) {}
    ~tracer() = default;
    tracer(const tracer& copy) = delete;
    tracer& operator=(const tracer& copy_assign) = delete;
    tracer(tracer&& move) = delete;
    tracer& operator=(tracer& move_assign) = delete;

    void trace(char* argv[]);

    void report_read(pid_t pid, tracee_file* file);
    void report_write(pid_t pid, tracee_file* file);

    bool is_bpf_enabled();

    static constexpr int GENERAL_PTRACE_FLAGS =
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;

  private:
    /* MARK: Private methods */

    void parent_task();
    void bpf_loop();
    void ptrace_loop();

    void child_task(char* argv[]);

    void setup_seccomp();

    /* MARK: Syscall handlers */

    void handle_open_syscall(tracee* process, const char* pathname /*, int flags, mode_t mode*/);
    void handle_openat_syscall(tracee* process, int dirfd,
                               const char* pathname /*, int flags, mode_t mode*/);
    void handle_close_syscall(tracee* process, int fd);
    void handle_write_syscall(tracee* process, int fd, char* buf, uint64_t len);
    void handle_read_syscall(tracee* process, int fd, char* buf, uint64_t len);
    void handle_syscall(tracee* process);

    /* MARK: Utilities */

    tracee* get_process(pid_t pid);
    tracee* wait_for_process();

    /* MARK: Private fields */

    FILE* m_result_file;
    pid_t m_child_pid = -1;
    bool m_bpf_enabled = true;
    std::unordered_map<pid_t, tracee> processes{};
};
