#pragma once

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <inttypes.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <vector>

class tracer;

struct tracee_file {

    template <typename T>
    tracee_file(T&& path, ino_t inode, dev_t dev)
        : m_path(std::forward<T>(path)), m_inode(inode), m_dev(dev), m_opened(true) {}
    tracee_file(ino_t inode, dev_t dev) : m_path({}), m_inode(inode), m_dev(dev), m_opened(true) {}
    tracee_file() : m_path({}), m_inode(-1), m_dev(-1), m_opened(false) {}

    std::string m_path;
    ino_t m_inode;
    dev_t m_dev;
    bool m_opened;
    bool m_read_occurred = false;
    bool m_write_occurred = false;
};

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

    void report_file_open(int fd, const char* process_addr);
    void report_file_close(int fd);
    void report_file_read(int fd, uint64_t bytes);
    void report_file_write(int fd, uint64_t bytes);

    /* MARK: Utilities */

    void exit_from_syscall();
    int64_t get_syscall_return_code();

    tracee_file* get_file(int fd);

    bool stopped_at_fork_or_clone();
    bool stopped_at_exec();
    bool stopped_at_seccomp();
    bool stopped_at_syscall();
    bool stopped_at_signal();
    unsigned long ptrace_get_event_message();

    void ptrace_get_registers(struct user_regs_struct* regs);
    void ptrace_continue();
    void ptrace_continue_to_syscall();
    void ptrace_detach();

    void inherit_opened_files_from(tracee* parent);
    void filter_opened_files();

    void wait();

    int get_pid();
    int get_status();

  private:
    /* MARK: Private methods */

    void ptrace_continue_with_request(enum __ptrace_request command);
    tracee_file* ensure_file(int fd);
    tracee_file* create_unnamed_file_for_fd(int fd);
    void debug_file_info(int fd);
    void ensure_fd_valid(int fd);

    void get_stat_for_fd(int fd, struct stat* file_stat);

    uint64_t read_word(void* process_addr);
    std::string read_string(const char* process_addr);

    // MARK: Private fields

    int m_pid = -1;
    int m_status = -1;

    bool m_is_at_syscall_entry = false;
    std::vector<tracee_file> m_opened_files = {};

    tracer* m_tracer;
};
