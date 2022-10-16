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

class Tracer {
  public:
    Tracer(const char* socket_path) : m_socket_path(socket_path) {}
    ~Tracer() = default;
    Tracer(const Tracer& copy) = delete;
    Tracer& operator=(const Tracer& copy_assign) = delete;
    Tracer(Tracer&& move) = delete;
    Tracer& operator=(Tracer& move_assign) = delete;

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

    void report_read_write_for_flags(Tracee* process, int fd, unsigned long long flags);
    void handle_open_syscall(Tracee* process, const char* pathname, int flags, mode_t mode);
    void handle_openat_syscall(Tracee* process, int dirfd, const char* pathname, int flags,
                               mode_t mode);
    void handle_openat2_syscall(Tracee* process, int dirfd, const char* pathname,
                                struct open_how* how, size_t size);

    void handle_creat_syscall(Tracee* process, const char* pathname, mode_t mode);
    void handle_unlink_syscall(Tracee* process, const char* pathname);
    void handle_unlinkat_syscall(Tracee* process, int dirfd, const char* path, int flag);
    void handle_syscall(Tracee* process);

    void handle_rename_syscall(Tracee* process, const char* oldpath, const char* newpath);
    void handle_renameat_syscall(Tracee* process, int olddirfd, const char* oldpath, int newdirfd,
                                 const char* newpath);
    void handle_renameat2_syscall(Tracee* process, int olddirfd, const char* oldpath, int newdirfd,
                                  const char* newpath, int flags);

    void handle_mkdir_at_path(Tracee* process, const std::filesystem::path& path);
    void handle_mkdir_syscall(Tracee* process, const char* pathname, mode_t /*mode*/);
    void handle_mkdirat_syscall(Tracee* process, int dirfd, const char* pathname, mode_t mode);
    void handle_rmdir_syscall(Tracee* process, const char* pathname);

    void handle_fork_clone(Tracee* process);
    void handle_possible_child(Tracee* process);

    /* MARK: Socket methods */
    bool connect_to_socket();
    void report_file_op(PS::TracerEventType event, pid_t pid, const std::filesystem::path& path,
                        struct stat* stat);
    void report_child(pid_t parent, pid_t child);
    void report_done();
    int wait_for_parmasan_acknowledgement();

    /* MARK: Utilities */

    Tracee* get_process(pid_t pid);
    Tracee* wait_for_process();
    void unlink_path(Tracee* process, const std::filesystem::path& path);

    /* MARK: Private fields */

    SerialBuffer m_output_buffer{};
    const char* m_socket_path;
    DaemonClient m_socket{};
    pid_t m_child_pid = -1;
    bool m_bpf_enabled = true;
    std::unordered_map<pid_t, Tracee> processes{};
};
