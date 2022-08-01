#pragma once

#include "client/daemon-client.hpp"
#include "seccomp.hpp"
#include "shared/serial-buffer.hpp"
#include "shared/tracer-event.hpp"
#include "tracee.hpp"
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>

class tracer {
  public:
    tracer(const std::string& socket_path) : m_socket_path(socket_path) {}
    ~tracer() = default;
    tracer(const tracer& copy) = delete;
    tracer& operator=(const tracer& copy_assign) = delete;
    tracer(tracer&& move) = delete;
    tracer& operator=(tracer& move_assign) = delete;

    void trace(char* argv[]);

    static constexpr int GENERAL_PTRACE_FLAGS = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                                                PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                                                PTRACE_O_TRACEEXEC;

  private:
    /* MARK: Private methods */

    void parent_task();
    void bpf_loop();
    void ptrace_loop();

    void child_task(char* argv[]) const;

    static void setup_seccomp();

    /* MARK: Syscall and fork handlers */

    void report_read_write_for_flags(tracee* process, int fd, unsigned long long flags);
    void handle_open_syscall(tracee* process, const char* pathname, int flags, mode_t mode);
    void handle_openat_syscall(tracee* process, int dirfd, const char* pathname, int flags,
                               mode_t mode);
    void handle_openat2_syscall(tracee* process, int dirfd, const char* pathname,
                                struct open_how* how, size_t size);

    void handle_creat_syscall(tracee* process, const char* pathname, mode_t mode);
    void handle_unlink_syscall(tracee* process, const char* pathname);
    void handle_unlinkat_syscall(tracee* process, int dirfd, const char* path, int flag);
    void handle_syscall(tracee* process);

    void handle_rename_syscall(tracee* process, const char* oldpath, const char* newpath);
    void handle_renameat_syscall(tracee* process, int olddirfd, const char* oldpath, int newdirfd,
                                 const char* newpath);
    void handle_renameat2_syscall(tracee* process, int olddirfd, const char* oldpath, int newdirfd,
                                  const char* newpath, int flags);

    void handle_mkdir_at_path(tracee* process, const std::string& path);
    void handle_mkdir_syscall(tracee* process, const char* pathname, mode_t /*mode*/);
    void handle_mkdirat_syscall(tracee* process, int dirfd, const char* pathname, mode_t mode);
    void handle_rmdir_syscall(tracee* process, const char* pathname);

    void handle_fork_clone(tracee* process);
    void handle_possible_child(tracee* process);

    /* MARK: Socket methods */
    bool connect_to_socket();
    void report_file_op(PS::TracerEventType event, pid_t pid, const std::string& path,
                        struct stat* stat);
    void report_child(pid_t parent, pid_t child);
    void report_done();
    int wait_for_parmasan_acknowledgement();

    /* MARK: Utilities */

    tracee* get_process(pid_t pid);
    tracee* wait_for_process();
    void unlink_path(tracee* process, const std::string& path);

    /* MARK: Private fields */

    SerialBuffer m_output_buffer{};
    std::string m_socket_path;
    DaemonClient m_socket{};
    pid_t m_child_pid = -1;
    bool m_bpf_enabled = true;
    std::unordered_map<pid_t, tracee> processes{};
};
