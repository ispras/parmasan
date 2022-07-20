#pragma once

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <inttypes.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <filesystem>
#include <vector>
// #include <linux/openat2.h>
#include "openat2.h"

class tracer;

class tracee {
  public:
    tracee() = default;
    ~tracee() = default;
    tracee(const tracee& copy) = delete;
    tracee& operator=(const tracee& copy_assign) = delete;
    tracee(tracee&& move) = default;
    tracee& operator=(tracee& move_assign) = default;

    bool initialized();
    void initialize(int pid, tracer* tracer);

    void set_at_syscall_entry(int status);
    bool is_at_syscall_entry();

    /* MARK: Utilities */

    void exit_from_syscall();
    int64_t get_syscall_return_code();

    bool stopped_at_fork_or_clone();
    bool stopped_at_exec();
    bool stopped_at_seccomp();
    bool stopped_at_syscall();
    bool stopped_at_signal();
    unsigned long ptrace_get_event_message();

    bool ptrace_get_registers(struct user_regs_struct* regs);
    void ptrace_continue();
    void ptrace_continue_to_syscall();
    void ptrace_detach();

    void wait();

    int get_pid();
    int get_status();

    void get_stat_for_fd(int fd, struct stat* file_stat);
    std::filesystem::path get_path_for_fd(int fd);
    std::filesystem::path get_cwd();
    uint64_t read_word(void* process_addr);
    std::string read_string(const char* process_addr);

  private:
    /* MARK: Private methods */

    void ptrace_continue_with_request(enum __ptrace_request command);

    // MARK: Private fields

    int m_pid = -1;
    int m_status = -1;
    bool m_is_at_syscall_entry = false;

    tracer* m_tracer;
};
