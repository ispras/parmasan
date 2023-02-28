
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "tracer.h"
#include "renameat2.h"
#include "tracee.h"

static char socket_buffer[PATH_MAX * 4] = {0};

#define TRACER_MESSAGE_PREFIX "TRACER %7d "

void tracer_trace(char* argv[])
{
    s_tracer tracer = {0};

    tracer.bpf_enabled = seccomp_available();
#ifdef DEBUG
    printf("Seccomp availability: %s\n", m_bpf_enabled ? "available" : "unavailable");
    if (!m_bpf_enabled) {
        printf("Falling back to PTRACE_SYSCALL tracing\n");
    }
#endif
    pid_t pid = fork();

    if (pid) {
        tracer.child_pid = pid;
        tracer_parent_task(&tracer);
    } else {
        tracer_child_task(&tracer, argv);
    }
}

void tracer_report_file_op(s_tracer* self, e_tracer_event_type type, pid_t pid, const char* path,
                           struct stat* stat)
{
    int len = snprintf(
        socket_buffer, sizeof(socket_buffer), TRACER_MESSAGE_PREFIX "%s %lu %s %d %lu %lu",
        getpid(), TRACER_EVENT_CODES[type], strlen(path), path, pid, stat->st_dev, stat->st_ino);

    send(self->socket_fd, socket_buffer, len, 0);
}

void tracer_report_child(s_tracer* self, pid_t parent, pid_t child)
{
    e_tracer_event_type type = TRACER_EVENT_CHILD;
    s_tracer_child_event event = {.pid = child, .ppid = parent};

    int len = snprintf(socket_buffer, sizeof(socket_buffer), TRACER_MESSAGE_PREFIX "%s %d %d",
                       getpid(), TRACER_EVENT_CODES[type], event.pid, event.ppid);

    send(self->socket_fd, socket_buffer, len, 0);

    tracer_wait_for_parmasan_acknowledgement(self);
}

void tracer_report_done(s_tracer* self)
{
    e_tracer_event_type event = TRACER_EVENT_DONE;

    int len = snprintf(socket_buffer, sizeof(socket_buffer), TRACER_MESSAGE_PREFIX "%s", getpid(),
                       TRACER_EVENT_CODES[event]);
    send(self->socket_fd, socket_buffer, len, 0);
}

int tracer_wait_for_parmasan_acknowledgement(s_tracer* self)
{
    char buffer[8] = {};

    while (1) {
        ssize_t length = read(self->socket_fd, buffer, sizeof(buffer));
        if (length < 0)
            return -1;

        if (strcmp(buffer, "ACK") == 0)
            return 0;
    }
}

bool tracer_connect_to_socket(s_tracer* self)
{
    // Read environment variable "PARMASAN_DAEMON_FD" to get the socket file descriptor
    char* fd_str = getenv("PARMASAN_DAEMON_FD");
    if (fd_str == NULL) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable not set\n");
        return false;
    }

    int fd = atoi(fd_str);
    if (fd < 0) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable is invalid\n");
        return false;
    }

    self->socket_fd = fd;

    int len =
        snprintf(socket_buffer, sizeof(socket_buffer), TRACER_MESSAGE_PREFIX "INIT", getpid());

    send(self->socket_fd, socket_buffer, len, 0);

    tracer_wait_for_parmasan_acknowledgement(self);

    return true;
}

void tracer_parent_task(s_tracer* self)
{
    if (!tracer_connect_to_socket(self)) {
        kill(self->child_pid, SIGKILL);
        return;
    }

    tracer_report_child(self, getpid(), self->child_pid);

    wait(NULL);

    if (self->bpf_enabled) {
        tracer_bpf_loop(self);
    } else {
        tracer_ptrace_loop(self);
    }

    tracer_report_done(self);
}

enum {
    TRACER_GENERAL_PTRACE_FLAGS = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                                  PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC
};

void tracer_bpf_loop(s_tracer* self)
{
    ptrace(PTRACE_SETOPTIONS, self->child_pid, 0,
           TRACER_GENERAL_PTRACE_FLAGS | PTRACE_O_TRACESECCOMP);

    s_tracee process = {self->child_pid, -1};
    tracee_ptrace_continue(&process);

    while (tracer_wait_for_process(&process) == 0) {
        if (tracee_stopped_at_seccomp(&process)) {
            tracer_handle_syscall(self, &process);
        } else {
            tracer_handle_possible_child(self, &process);
        }

        tracee_ptrace_continue(&process);
    }
}

void tracer_ptrace_loop(s_tracer* self)
{
    ptrace(PTRACE_SETOPTIONS, self->child_pid, 0, TRACER_GENERAL_PTRACE_FLAGS);
    s_tracee process = {self->child_pid, -1};
    tracee_ptrace_continue_to_syscall(&process);

    while (tracer_wait_for_process(&process) == 0) {
        if (tracee_stopped_at_syscall(&process)) {
            tracer_handle_syscall(self, &process);

            // It's necessary to exit from syscall
            // explicitly when in pure-ptrace mode,
            // since otherwise some syscalls will
            // end up being handled twice

            tracee_exit_from_syscall(&process);
        } else {
            tracer_handle_possible_child(self, &process);
        }

        tracee_ptrace_continue_to_syscall(&process);
    }
}

static bool tracer_setup_seccomp()
{

    struct sock_filter filter[] = {
        // Kill the process if it is not in 64-bit mode.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        // Check the syscall id
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdirat, 12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdir, 11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rmdir, 10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rename, 9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_renameat, 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_renameat2, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unlinkat, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unlink, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_creat, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };

    struct sock_fprog prog = {sizeof(filter) / sizeof(*filter), filter};
    return set_seccomp_filter(&prog);
}

void tracer_child_task(s_tracer* self, char* argv[])
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);

    if (self->bpf_enabled) {
        tracer_setup_seccomp();
    }

    execvp(argv[0], argv);
    perror("execvp");
    exit(-1);
}

/* MARK: Syscall handlers */

void tracer_report_read_write_for_flags(s_tracer* self, s_tracee* process, int fd,
                                        unsigned long long flags)
{
    if (fd < 0)
        return;
    int pid = process->pid;
    struct stat file_stat = {0};
    tracee_get_stat_for_fd(process, fd, &file_stat);

    char path[PATH_MAX + 1];

    tracee_get_path_for_fd(process, fd, path, PATH_MAX + 1);

    flags &= O_ACCMODE;

    e_tracer_event_type event;

    if (flags == O_RDONLY) {
        event = TRACER_EVENT_READ;
    } else if (flags == O_WRONLY) {
        event = TRACER_EVENT_WRITE;
    } else if (flags == O_RDWR) {
        event = TRACER_EVENT_READ_WRITE;
    } else {
        return;
    }

    tracer_report_file_op(self, event, pid, path, &file_stat);
}

void tracer_unlink_path(s_tracer* self, s_tracee* process, const char* path)
{
    struct stat file_stat = {0};

    // Using lstat here as unlink does not resolve symlinks
    if (lstat(path, &file_stat) < 0)
        return;

    bool is_inode_released = file_stat.st_nlink <= 1;
    bool is_unlink_successful = tracee_get_syscall_return_code(process) == 0;

    tracer_report_file_op(self, TRACER_EVENT_UNLINK, process->pid, path, &file_stat);

    if (is_inode_released && is_unlink_successful) {
        tracer_report_file_op(self, TRACER_EVENT_INODE_UNLINK, process->pid, path, &file_stat);
    }
}

static void tracer_handle_unlinkat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                           const char* pathname, int flag)
{
    char path[PATH_MAX + 1];

    int path_length = -1;

    if (dirfd == AT_FDCWD) {
        path_length = tracee_get_cwd(process, path, PATH_MAX + 1);
    } else {
        path_length = tracee_get_path_for_fd(process, dirfd, path, PATH_MAX + 1);
    }

    if (path_length < 0)
        return;

    if (path[path_length - 1] != '/') {
        path[path_length] = '/';
        path_length++;
    }

    tracee_read_string(process, pathname, path + path_length, PATH_MAX + 1 - path_length);

    char normalized_path[PATH_MAX + 1];
    realpath(path, normalized_path);

    tracer_unlink_path(self, process, normalized_path);
}

static void tracer_handle_unlink_syscall(s_tracer* self, s_tracee* process, const char* pathname)
{
    tracer_handle_unlinkat_syscall(self, process, AT_FDCWD, pathname, 0);
}

static void tracer_handle_open_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                       int flags, mode_t mode)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, flags);
}

static void tracer_handle_openat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                         const char* pathname, int flags, mode_t mode)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, flags);
}

static void tracer_handle_openat2_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                          const char* pathname, struct open_how* how, size_t size)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, how->flags);
}

static void tracer_handle_creat_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                        mode_t mode)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, O_WRONLY | O_CREAT | O_TRUNC);
}

static void tracer_handle_mkdir_at_path(s_tracer* self, s_tracee* process, const char* path)
{
    // Wait until process is out from syscall to call stat
    // on newly created directory.

    tracee_exit_from_syscall(process);
    struct stat file_stat = {0};

    if (stat(path, &file_stat) < 0)
        return;

    tracer_report_file_op(self, TRACER_EVENT_WRITE, process->pid, path, &file_stat);
}

static void tracer_handle_mkdirat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                          const char* pathname, mode_t mode)
{
    char path[PATH_MAX + 1];

    int path_length = -1;

    if (dirfd == AT_FDCWD) {
        path_length = tracee_get_cwd(process, path, PATH_MAX + 1);
    } else {
        path_length = tracee_get_path_for_fd(process, dirfd, path, PATH_MAX + 1);
    }

    if (path_length < 0)
        return;

    if (path[path_length - 1] != '/') {
        path[path_length] = '/';
        path_length++;
    }

    tracee_read_string(process, pathname, path + path_length, PATH_MAX + 1 - path_length);

    char normalized_path[PATH_MAX + 1];
    realpath(path, normalized_path);

    tracer_handle_mkdir_at_path(self, process, normalized_path);
}

static void tracer_handle_mkdir_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                        mode_t mode)
{
    tracer_handle_mkdirat_syscall(self, process, AT_FDCWD, pathname, mode);
}

static void tracer_handle_rmdir_syscall(s_tracer* self, s_tracee* process, const char* pathname)
{
    char path[PATH_MAX + 1];

    ssize_t length = tracee_get_cwd(process, path, PATH_MAX + 1);

    if (length < 0) {
        return;
    }

    if (path[length - 1] != '/') {
        path[length] = '/';
        length++;
    }

    strncpy(path + length, pathname, PATH_MAX + 1 - length);

    char normalized_path[PATH_MAX + 1];
    realpath(path, normalized_path);

    tracer_unlink_path(self, process, normalized_path);
}

// Handle rename as unlink of destination
static void tracer_handle_rename_syscall(s_tracer* self, s_tracee* process, const char* oldpath,
                                         const char* newpath)
{
    tracer_handle_unlink_syscall(self, process, newpath);
}

static void tracer_handle_renameat_syscall(s_tracer* self, s_tracee* process, int olddirfd,
                                           const char* oldpath, int newdirfd, const char* newpath)
{
    tracer_handle_unlinkat_syscall(self, process, newdirfd, newpath, 0);
}

static void tracer_handle_renameat2_syscall(s_tracer* self, s_tracee* process, int olddirfd,
                                            const char* oldpath, int newdirfd, const char* newpath,
                                            int flags)
{
    if (flags & RENAME_NOREPLACE || flags & RENAME_EXCHANGE)
        return;

    tracer_handle_unlinkat_syscall(self, process, newdirfd, newpath, 0);
}

void tracer_handle_syscall(s_tracer* self, s_tracee* process)
{
    struct user_regs_struct state = {};

    // Kill the process if architecture is not x86-64
    if (!tracee_ptrace_get_registers(process, &state)) {
        kill(process->pid, SIGKILL);
        return;
    }

    uint64_t syscall_num = state.orig_rax;
    uint64_t arg0 = state.rdi;
    uint64_t arg1 = state.rsi;
    uint64_t arg2 = state.rdx;
    uint64_t arg3 = state.r10;

    switch (syscall_num) {
    case SYS_open:
        tracer_handle_open_syscall(self, process, (char*)arg0, (int)arg1, arg2);
        break;
    case SYS_openat:
        tracer_handle_openat_syscall(self, process, (int)arg0, (char*)arg1, (int)arg2, arg3);
        break;
    case SYS_openat2:
        tracer_handle_openat2_syscall(self, process, (int)arg0, (char*)arg1, (struct open_how*)arg2,
                                      arg3);
        break;
    case SYS_creat:
        tracer_handle_creat_syscall(self, process, (const char*)arg0, state.rsi);
        break;
    case SYS_unlink:
        tracer_handle_unlink_syscall(self, process, (char*)arg0);
        break;
    case SYS_unlinkat:
        tracer_handle_unlinkat_syscall(self, process, (int)arg0, (char*)arg1, (int)arg2);
        break;
    case SYS_rename:
        tracer_handle_rename_syscall(self, process, (char*)arg0, (char*)arg1);
        break;
    case SYS_renameat:
        tracer_handle_renameat_syscall(self, process, (int)arg0, (char*)arg1, (int)arg2,
                                       (char*)(arg3));
        break;
    case SYS_renameat2:
        tracer_handle_renameat2_syscall(self, process, (int)arg0, (char*)arg1, (int)arg2,
                                        (char*)(arg3), (int)(state.r11));
        break;
    case SYS_mkdir:
        tracer_handle_mkdir_syscall(self, process, (char*)arg0, (mode_t)arg1);
        break;
    case SYS_mkdirat:
        tracer_handle_mkdirat_syscall(self, process, (int)arg0, (char*)arg1, (mode_t)arg2);
        break;
    case SYS_rmdir:
        tracer_handle_rmdir_syscall(self, process, (char*)arg0);
        break;
    default:
        if (self->bpf_enabled) {
            fprintf(stderr, "Syscall %ld is not handled by the tracer\n", syscall_num);
            exit(1);
        }
        break;
    }
}

void tracer_handle_fork_clone(s_tracer* self, s_tracee* process)
{
    pid_t forked_pid = (pid_t)(tracee_ptrace_get_event_message(process));
    tracer_report_child(self, process->pid, forked_pid);
}

/* MARK: Utilities */

void tracer_handle_possible_child(s_tracer* self, s_tracee* process)
{
    if (tracee_stopped_at_fork_or_clone(process)) {
        tracer_handle_fork_clone(self, process);
    }
}

int tracer_wait_for_process(s_tracee* out_process)
{
    int status = -1;
    pid_t pid = wait(&status);
    if (pid > 0) {
        out_process->pid = pid;
        out_process->status = status;
        return 0;
    }
    return 1;
}
