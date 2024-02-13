
#include "tracer.h"
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "path.h"
#include "renameat2.h"
#include "tracee.h"

#define PARMASAN_SYNC "SYNC  "
#define PARMASAN_ASYNC "ASYNC "
#define LONG_PATH_MAX (PATH_MAX * 4)

static char socket_buffer[LONG_PATH_MAX] = {0};
char* message_buffer = socket_buffer + sizeof(PARMASAN_SYNC) - 1;
#define PARMASAN_MAX_MSG_LEN (sizeof(socket_buffer) - sizeof(PARMASAN_SYNC) + 1)

void tracer_trace(char* argv[])
{
    s_tracer tracer = {0};

    tracer_construct(&tracer);
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
        return;
    }

    tracer_destroy(&tracer);
}

void tracer_construct(s_tracer* self)
{
    self->socket_fd = -1;
}

void tracer_destroy(s_tracer* self)
{
    if (self->socket_fd >= 0) {
        close(self->socket_fd);
        self->socket_fd = -1;
    }
}

void tracer_send_message(s_tracer* self, int len, bool sync)
{
    if (self->parmasan_interactive_mode == PARMASAN_INTERACTIVE_SYNC) {
        sync = true;
    }

    if (sync) {
        memcpy(socket_buffer, PARMASAN_SYNC, sizeof(PARMASAN_SYNC) - 1);
    } else {
        memcpy(socket_buffer, PARMASAN_ASYNC, sizeof(PARMASAN_ASYNC) - 1);
    }

    send(self->socket_fd, socket_buffer, len + sizeof(PARMASAN_SYNC) - 1, 0);

    if (sync) {
        tracer_wait_for_parmasan_acknowledgement(self);
    }
}

void tracer_report_file_op(s_tracer* self, e_tracer_event_type type, pid_t pid, const char* path,
                           struct stat* stat, int retcode)
{
    int len = snprintf(
        message_buffer, PARMASAN_MAX_MSG_LEN, "%s %lu %s %d %lu %lu %d",
        TRACER_EVENT_CODES[type], strlen(path), path, pid, stat->st_dev, stat->st_ino,
        retcode);

    tracer_send_message(self, len, false);
}

void tracer_report_child_with_cmdline(s_tracer* self, pid_t parent, pid_t child, size_t cmdlen,
                                      const char* cmdline)
{
    e_tracer_event_type type = TRACER_EVENT_CHILD;
    s_tracer_child_event event = {.pid = child, .ppid = parent};

    if (!cmdline) {
        cmdlen = 0;
        cmdline = "";
    }

    bool crop = cmdlen > PATH_MAX;

    if (crop) {
        cmdlen = PATH_MAX;
    }

    int len = snprintf(message_buffer, PARMASAN_MAX_MSG_LEN, "%s %d %d %ld ",
                       TRACER_EVENT_CODES[type], event.pid, event.ppid, cmdlen);
    memcpy(message_buffer + len, cmdline, cmdlen);

    if (crop) {
        message_buffer[len + cmdlen - 1] = '\0';
    }

    len += cmdlen;

    tracer_send_message(self, len, true);
}

void tracer_report_die(s_tracer* self, pid_t pid)
{
    e_tracer_event_type event = TRACER_EVENT_DIE;

    int len = snprintf(message_buffer, PARMASAN_MAX_MSG_LEN, "%s %d",
                       TRACER_EVENT_CODES[event], pid);
    tracer_send_message(self, len, false);
}

int tracer_set_sync_mode(s_tracer* self)
{
    const char* parmasan_mode = getenv("PARMASAN_SYNC_MODE");

    if (parmasan_mode == NULL) {
        fprintf(stderr, "PARMASAN_SYNC_MODE environment variable not set\n");
        return -1;
    }

    char mode = PARMASAN_INTERACTIVE_NONE;

    switch (parmasan_mode[0]) {
    case PARMASAN_INTERACTIVE_NONE:
    case PARMASAN_INTERACTIVE_FAST:
    case PARMASAN_INTERACTIVE_SYNC:
        self->parmasan_interactive_mode = (e_parmasan_interactive_mode)mode;
        return 0;
    default:
        break;
    }

    fprintf(stderr, "PARMASAN_SYNC_MODE environment variable is invalid\n");
    return -1;
}

int tracer_wait_for_parmasan_acknowledgement(s_tracer* self)
{
    char buffer[8] = {};

    ssize_t length = read(self->socket_fd, buffer, sizeof(buffer));
    if (length < 0)
        return -1;

    if (strcmp(buffer, "ACK") == 0)
        return 0;

    return -1;
}

bool tracer_connect_to_socket(s_tracer* self)
{
    // Read the socket path
    char* sock_str = getenv("PARMASAN_DAEMON_SOCK");
    if (sock_str == NULL) {
        fprintf(stderr, "PARMASAN_DAEMON_SOCK environment variable not set\n");
        goto error;
    }

    if (*sock_str == '\0') {
        fprintf(stderr, "PARMASAN_DAEMON_SOCK environment variable must not be empty\n");
        goto error;
    }

    if (tracer_set_sync_mode(self) < 0) {
        goto error;
    }

    struct sockaddr_un server_address = {};
    server_address.sun_family = AF_UNIX;

    size_t socket_length = strlen(sock_str);

    if (socket_length >= sizeof(server_address.sun_path)) {
        socket_length = sizeof(server_address.sun_path) - 1;
    }

    memcpy(server_address.sun_path, sock_str, socket_length);

    if (sock_str[0] == '$') {
        server_address.sun_path[0] = '\0';
    }

    self->socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (self->socket_fd < 0) {
        perror("socket");
        goto error;
    }

    int connection_result = connect(self->socket_fd, (const struct sockaddr*)&server_address,
                                    sizeof(server_address.sun_family) + socket_length);

    if (connection_result < 0) {
        perror("connect");
        goto error;
    }

    // Send "INIT TRACER" packet
    int len = snprintf(message_buffer, PARMASAN_MAX_MSG_LEN, "INIT TRACER");
    tracer_send_message(self, len, true);

    return true;

error:
    if (self->socket_fd >= 0) {
        close(self->socket_fd);
        self->socket_fd = -1;
    }

    return false;
}

static char* get_cmdline(pid_t pid, size_t* len)
{
    char fd_path[64] = {0};
    sprintf(fd_path, "/proc/%d/cmdline", pid);

    FILE* file = fopen(fd_path, "r");

    if (!file) {
        perror("get_cmdline");
        goto err_early;
    }

    size_t buffer_size = 0;
    char* buffer = NULL;
    char tmp_buffer[256] = {};
    FILE* memstream = open_memstream(&buffer, &buffer_size);

    while (true) {
        size_t bytes_read = fread(tmp_buffer, 1, sizeof(tmp_buffer), file);

        if (bytes_read <= 0) {
            if (feof(file)) {
                break;
            } else if (ferror(file)) {
                perror("fread");
                goto err;
            }
        }

        if (fwrite(tmp_buffer, 1, bytes_read, memstream) != bytes_read) {
            perror("fwrite");
            goto err;
        }
    }

    fputc(0, memstream);
    fclose(memstream);
    fclose(file);

    *len = buffer_size;
    return buffer;

err:
    free(buffer);
    fclose(memstream);
    fclose(file);

err_early:
    *len = SIZE_MAX;
    return NULL;
}

static void tracer_report_child(s_tracer* self, pid_t parent, pid_t child)
{
    size_t cmdlen = SIZE_MAX;
    char* cmdline = get_cmdline(child, &cmdlen);
    tracer_report_child_with_cmdline(self, parent, child, cmdlen, cmdline);
    free(cmdline);
}

void tracer_parent_task(s_tracer* self)
{
    if (!tracer_connect_to_socket(self)) {
        kill(self->child_pid, SIGKILL);
        return;
    }

    pidset_create(&self->stopped_pids, 29);

    ptrace(PTRACE_SEIZE, self->child_pid, 0, 0);

    tracer_report_child(self, getpid(), self->child_pid);

    wait(NULL);

    if (self->bpf_enabled) {
        tracer_bpf_loop(self);
    } else {
        tracer_ptrace_loop(self);
    }

    tracer_report_die(self, getpid());

    pidset_destroy(&self->stopped_pids);
}

enum {
    TRACER_GENERAL_PTRACE_FLAGS = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                                  PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                  PTRACE_O_TRACEEXIT
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
        } else if (tracee_stopped_at_child_init(&process)) {
            // Do not let the child run before we receive the clone or fork
            // event from the parent. Otherwise, the process tree will be
            // inconsistent.
            pidset_add(&self->stopped_pids, process.pid);
            continue;
        } else if (tracee_exited(&process)) {
            tracer_report_die(self, process.pid);
        } else if (tracee_stopped_at_fork_or_clone(&process)) {
            tracer_handle_fork_or_clone(self, &process);
        } else if (tracee_stopped_at_exec(&process)) {
            tracer_handle_exec(self, &process);
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
        } else if (tracee_stopped_at_child_init(&process)) {
            // Do not let the child run before we receive the clone or fork
            // event from the parent. Otherwise, the process tree will be
            // inconsistent.
            pidset_add(&self->stopped_pids, process.pid);
            continue;
        } else if (tracee_exited(&process)) {
            tracer_report_die(self, process.pid);
        } else if (tracee_stopped_at_fork_or_clone(&process)) {
            tracer_handle_fork_or_clone(self, &process);
        } else if (tracee_stopped_at_exec(&process)) {
            tracer_handle_exec(self, &process);
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
    raise(SIGSTOP);

    if (self->bpf_enabled) {
        tracer_setup_seccomp();
    }

    execvp(argv[0], argv);
    perror("execvp");
    exit(-1);
}

static ssize_t tracee_get_path_for_dirfd(s_tracee* process, int dirfd, char path[PATH_MAX])
{
    ssize_t path_length = -1;

    if (dirfd == AT_FDCWD) {
        path_length = tracee_get_cwd(process, path, PATH_MAX + 1);
    } else {
        path_length = tracee_get_path_for_fd(process, dirfd, path, PATH_MAX + 1);
    }

    if (path_length < 0)
        return -1;

    if (path[path_length - 1] != '/') {
        if (path_length == PATH_MAX)
            return -1;

        path[path_length] = '/';
        path_length++;
    }

    path[path_length] = '\0';
    return path_length;
}

static ssize_t tracee_get_normalized_path(s_tracee* process, int dirfd, const char* pathname,
                                          char path[PATH_MAX])
{
    ssize_t path_length = tracee_get_path_for_dirfd(process, dirfd, path);
    if (path_length < 0) {
        return -1;
    }

    int length = tracee_read_string(process, pathname, path + path_length,
                                    PATH_MAX + 1 - path_length);

    path[length + path_length] = '\0';
    if (path[path_length] == '/') {
        // If the path is absolute, copy it to the beginning of the buffer.
        memmove(path, path + path_length, length + 1);
    }

    return (ssize_t)normalize_path(path);
}

static ssize_t resolve_symlink(char* path, ssize_t path_length, ssize_t path_capacity)
{
    // The trick here is to write the link target to the end of the path, after a "/../"
    // string, and call normalize_path() on the resulting string afterward.

    char up_dir[4] = "/../";

    ssize_t link_offset = path_length + (ssize_t)sizeof(up_dir);
    ssize_t readlink_length = readlink(path, path + link_offset, path_capacity - 1 - link_offset);

    if (readlink_length < 0)
        return readlink_length;

    // If the link target is absolute, we can just replace the path with it.
    if (path[link_offset] == '/') {
        memmove(path, path + link_offset, readlink_length);
        path[readlink_length] = '\0';
        return readlink_length;
    }

    memcpy(path + path_length, up_dir, sizeof(up_dir));
    path_length = link_offset + readlink_length;
    path[path_length] = '\0';

    return (ssize_t)normalize_path(path);
}

/* MARK: Syscall handlers */

void tracer_report_read_write_for_flags(s_tracer* self, s_tracee* process, int fd,
                                        unsigned long long flags, const char* pathname, int dirfd)
{
    char path[LONG_PATH_MAX];

    ssize_t path_length = tracee_get_normalized_path(process, dirfd, pathname, path);

    if (path_length < 0)
        return;

    int pid = process->pid;
    struct stat file_stat = {0};

    if (lstat(path, &file_stat) < 0) {
        file_stat.st_ino = 0;
    }

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

    // If file is a symlink, iterate through symlinks until the actual file is found.
    // For each symlink, report a read event.
    while (S_ISLNK(file_stat.st_mode)) {
        tracer_report_file_op(self, TRACER_EVENT_READ, pid, path, &file_stat, fd);

        path_length = resolve_symlink(path, path_length, sizeof(path));

        if (lstat(path, &file_stat) < 0) {
            perror("lstat");
            return;
        }
    }

    tracer_report_file_op(self, event, pid, path, &file_stat, fd);
}

void tracer_unlink_path(s_tracer* self, s_tracee* process, const char* path)
{
    struct stat file_stat = {0};

    // Using lstat here as unlink does not resolve symlinks
    if (lstat(path, &file_stat) < 0) {
        file_stat.st_ino = 0;
    }

    int retcode = (int)tracee_get_syscall_return_code(process);

    tracer_report_file_op(self, TRACER_EVENT_UNLINK, process->pid, path, &file_stat, retcode);

    if (retcode != 0) {
        return;
    }

    bool is_inode_released = false;

    if ((file_stat.st_mode & S_IFMT) == S_IFDIR) {
        is_inode_released = file_stat.st_nlink <= 2;
    } else {
        is_inode_released = file_stat.st_nlink <= 1;
    }

    if (is_inode_released) {
        tracer_report_file_op(self, TRACER_EVENT_TOTAL_UNLINK, process->pid, path, &file_stat,
                              retcode);
    }
}

static void tracer_handle_unlinkat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                           const char* pathname, int /* flag */)
{
    char path[PATH_MAX + 1];

    if (tracee_get_normalized_path(process, dirfd, pathname, path) < 0)
        return;

    tracer_unlink_path(self, process, path);
}

static void tracer_handle_unlink_syscall(s_tracer* self, s_tracee* process, const char* pathname)
{
    tracer_handle_unlinkat_syscall(self, process, AT_FDCWD, pathname, 0);
}

static void tracer_handle_open_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                       int flags, mode_t /* mode */)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, flags, pathname, AT_FDCWD);
}

static void tracer_handle_openat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                         const char* pathname, int flags, mode_t /* mode */)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, flags, pathname, dirfd);
}

static void tracer_handle_openat2_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                          const char* pathname, struct open_how* how,
                                          size_t /* size */)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, how->flags, pathname, dirfd);
}

static void tracer_handle_creat_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                        mode_t /* mode */)
{
    int fd = (int)(tracee_get_syscall_return_code(process));
    tracer_report_read_write_for_flags(self, process, fd, O_WRONLY | O_CREAT | O_TRUNC, pathname,
                                       AT_FDCWD);
}

static void tracer_handle_mkdir_at_path(s_tracer* self, s_tracee* process, const char* path)
{
    // Wait until process is out from syscall to call stat
    // on newly created directory.

    int retcode = (int)tracee_get_syscall_return_code(process);

    struct stat file_stat = {0};

    if (stat(path, &file_stat) < 0) {
        file_stat.st_ino = 0;
    }

    tracer_report_file_op(self, TRACER_EVENT_WRITE, process->pid, path, &file_stat, retcode);
}

static void tracer_handle_mkdirat_syscall(s_tracer* self, s_tracee* process, int dirfd,
                                          const char* pathname, mode_t /* mode */)
{
    char path[PATH_MAX + 1];

    if (tracee_get_normalized_path(process, dirfd, pathname, path) < 0)
        return;

    tracer_handle_mkdir_at_path(self, process, path);
}

static void tracer_handle_mkdir_syscall(s_tracer* self, s_tracee* process, const char* pathname,
                                        mode_t mode)
{
    tracer_handle_mkdirat_syscall(self, process, AT_FDCWD, pathname, mode);
}

static void tracer_handle_rmdir_syscall(s_tracer* self, s_tracee* process, const char* pathname)
{
    char path[PATH_MAX + 1];

    if (tracee_get_normalized_path(process, AT_FDCWD, pathname, path) < 0)
        return;

    tracer_unlink_path(self, process, path);
}

// Handle rename as unlink of destination
static void tracer_handle_rename_syscall(s_tracer* self, s_tracee* process,
                                         const char* /* oldpath */, const char* newpath)
{
    tracer_handle_unlink_syscall(self, process, newpath);
}

static void tracer_handle_renameat_syscall(s_tracer* self, s_tracee* process, int /* olddirfd */,
                                           const char* /* oldpath */, int newdirfd,
                                           const char* newpath)
{
    tracer_handle_unlinkat_syscall(self, process, newdirfd, newpath, 0);
}

static void tracer_handle_renameat2_syscall(s_tracer* self, s_tracee* process, int /* olddirfd */,
                                            const char* /* oldpath */, int newdirfd,
                                            const char* newpath, int flags)
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
        tracer_handle_openat2_syscall(self, process, (int)arg0, (char*)arg1,
                                      (struct open_how*)arg2, arg3);
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

void tracer_handle_fork_or_clone(s_tracer* self, s_tracee* process)
{
    pid_t forked_pid = (pid_t)(tracee_ptrace_get_event_message(process));

    // Check if this pid was stopped with PTRACE_EVENT_STOP event.
    bool is_waiting = pidset_contains(&self->stopped_pids, forked_pid);

    if (!is_waiting) {
        // The process was not stopped with PTRACE_EVENT_STOP event,
        // so wait for it here to be able to send PTRACE_CONT to it
        // and let it continue its execution.
        int status = 0;
        waitpid(forked_pid, &status, 0);
    } else {
        pidset_remove(&self->stopped_pids, forked_pid);
    }

    tracer_report_child(self, process->pid, forked_pid);

    // Here the child is stopped at its first instruction.
    // Allow the child to continue its execution.
    ptrace(PTRACE_CONT, forked_pid, NULL, NULL);
}

void tracer_handle_exec(s_tracer* self, s_tracee* process)
{
    // When the traced executable performs an exec, the tracer sends
    // a repeated `child` message for this process with new cmdline.
    // This allows for parmasan to have the correct argv for
    // processes created with fork/exec.

    tracer_report_child(self, process->pid, process->pid);

    // Here the child is stopped at its first instruction.
    // Allow the child to continue its execution.
    ptrace(PTRACE_CONT, process->pid, NULL, NULL);
}

/* MARK: Utilities */

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
