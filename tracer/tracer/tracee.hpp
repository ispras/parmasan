#pragma once

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <inttypes.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <vector>
// #include <linux/openat2.h>
#include "openat2.h"

class Tracer;

class Tracee {
  public:
    Tracee() = default;
    ~Tracee() = default;
    Tracee(const Tracee& copy) = delete;
    Tracee& operator=(const Tracee& copy_assign) = delete;
    Tracee(Tracee&& move) = default;
    Tracee& operator=(Tracee&& move_assign) = default;

    bool initialized() const;
    void initialize(int pid);

    void set_at_syscall_entry(int status);
    bool is_at_syscall_entry() const;

    /* MARK: Utilities */

    void exit_from_syscall();
    unsigned long long int get_syscall_return_code();

    bool stopped_at_fork_or_clone();
    bool stopped_at_seccomp();
    bool stopped_at_syscall();
    bool stopped_at_signal();
    unsigned long ptrace_get_event_message();

    bool ptrace_get_registers(struct user_regs_struct* regs);
    void ptrace_continue();
    void ptrace_continue_to_syscall();

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
};
