#pragma once

#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <inttypes.h>
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <cassert>
#include <sstream>
#include <vector>

class tracer;

struct tracer_process_file {
    std::string m_path;
    ino_t m_inode;
    bool m_opened;
    bool m_read_occurred;
    bool m_write_occurred;
};

class tracer_process {
public:

    tracer_process() = default;
    ~tracer_process() = default;
    tracer_process(const tracer_process& copy) = delete;
    tracer_process& operator=(const tracer_process& copy_assign) = delete;
    tracer_process(tracer_process&& move) = default;
    tracer_process& operator=(tracer_process& move_assign) = default;

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

    tracer_process_file* get_file(int fd);

    bool stopped_at_seccomp();
    bool stopped_at_syscall();
    bool stopped_at_signal();
    bool exitted();

    void ptrace_get_registers(struct user_regs_struct* regs);
    void ptrace_continue();
    void ptrace_continue_to_syscall();
    void ptrace_detach();

    void wait();

    int get_pid();
    int get_status();

private:

    /* MARK: Private methods */

    tracer_process_file* ensure_file(int fd);
    tracer_process_file* create_unnamed_file_for_fd(int fd);
    void debug_file_info(int fd);
    void ensure_fd_valid(int fd);

    ino_t get_inode_for_fd(int fd);

    uint64_t read_word(void* process_addr);
    std::string read_string(const char* process_addr);

    // MARK: Private fields

    int m_pid = -1;
    int m_status = -1;

    bool m_is_at_syscall_entry = false;
    std::vector<tracer_process_file> m_opened_files = {};

    tracer* m_tracer;
};