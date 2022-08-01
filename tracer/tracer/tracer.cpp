
#include "tracer.hpp"
#include "shared/connection-state.hpp"
#include "tracee.hpp"
#include <cassert>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

void tracer::trace(char* argv[]) {
    m_bpf_enabled = seccomp_available();
#ifdef DEBUG
    printf("Seccomp availability: %s\n", m_bpf_enabled ? "available" : "unavailable");
    if (!m_bpf_enabled) {
        printf("Falling back to PTRACE_SYSCALL tracing\n");
    }
#endif
    pid_t pid = fork();

    if (pid) {
        m_child_pid = pid;
        parent_task();
    } else {
        child_task(argv);
    }
}

void tracer::report_file_op(PS::TracerEventType type, pid_t pid, const std::string& path,
                            struct stat* stat) {
    assert(path == std::filesystem::weakly_canonical(path));
    PS::TracerFileEvent event = {.pid = pid,
                                 .file_entry = {.device = stat->st_dev, .inode = stat->st_ino}};
    m_output_buffer.clear();
    m_output_buffer.write(&type);
    m_output_buffer.write(&event);
    m_output_buffer.write_string(path);
    m_socket.send(m_output_buffer.data(), m_output_buffer.size());
}

void tracer::report_child(pid_t parent, pid_t child) {
    PS::TracerEventType type = PS::TRACER_EVENT_CHILD;
    PS::TracerChildEvent event{.pid = child, .ppid = parent};
    m_output_buffer.clear();
    m_output_buffer.write(&type);
    m_output_buffer.write(&event);
    m_socket.send(m_output_buffer.data(), m_output_buffer.size());
    wait_for_parmasan_acknowledgement();
}

void tracer::report_done() {
    PS::TracerEventType event = PS::TRACER_EVENT_DONE;
    m_output_buffer.clear();
    m_output_buffer.write(&event);
    m_socket.send(m_output_buffer.data(), m_output_buffer.size());
}

int tracer::wait_for_parmasan_acknowledgement() {
    char buffer[8] = {};

    while (1) {
        ssize_t length = m_socket.read(buffer, sizeof(buffer));
        if (length < 0)
            return -1;

        if (strcmp(buffer, "ACK") == 0)
            return 0;
    }
}

bool tracer::connect_to_socket() {
    if (!m_socket.setup_socket()) {
        fprintf(stderr, "Failed to setup daemon communication socket\n");
        return false;
    }

    if (!m_socket.connect(m_socket_path.c_str())) {
        fprintf(stderr, "Failed to connect to parmasan daemon. Is it up?\n");
        return false;
    }

    // Send initialization packet
    ConnectionState state = CONNECTION_STATE_TRACER_PROCESS;
    m_output_buffer.clear();
    m_output_buffer.write(&state);
    m_socket.send(m_output_buffer.data(), m_output_buffer.size());

    return true;
}

void tracer::parent_task() {
    if (!connect_to_socket()) {
        kill(m_child_pid, SIGKILL);
        return;
    }

    report_child(getpid(), m_child_pid);

    wait(nullptr);

    if (m_bpf_enabled) {
        bpf_loop();
    } else {
        ptrace_loop();
    }

    report_done();
    m_socket.close();
}

void tracer::bpf_loop() {
    ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, tracer::GENERAL_PTRACE_FLAGS | PTRACE_O_TRACESECCOMP);

    tracee* process = get_process(m_child_pid);
    process->ptrace_continue();

    while ((process = wait_for_process())) {
        if (process->stopped_at_seccomp()) {
            handle_syscall(process);
        } else {
            handle_possible_child(process);
        }

        process->ptrace_continue();
    }
}

void tracer::ptrace_loop() {
    ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, tracer::GENERAL_PTRACE_FLAGS);
    tracee* process = get_process(m_child_pid);
    process->ptrace_continue_to_syscall();

    while ((process = wait_for_process())) {
        if (process->stopped_at_syscall()) {
            handle_syscall(process);

            // It's necessary to exit from syscall
            // explicitly when in pure-ptrace mode,
            // since otherwise some syscalls will
            // end up being handled twice

            process->exit_from_syscall();
        } else {
            handle_possible_child(process);
        }

        process->ptrace_continue_to_syscall();
    }
}

void tracer::child_task(char* argv[]) const {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);

    if (m_bpf_enabled) {
        setup_seccomp();
    }

    execvp(argv[0], argv);
    perror("execvp");
    exit(-1);
}

void tracer::setup_seccomp() {

    struct sock_filter filter[] = {
        // Kill the process if it is not in 64-bit mode.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        // Check the syscall id
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rmdir, 10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rename, 9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat, 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat2, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlink, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)};

    struct sock_fprog prog = {sizeof(filter) / sizeof(*filter), filter};
    bool filter_set_success = set_seccomp_filter(&prog);
    assert(filter_set_success);
}

/* MARK: Syscall handlers */

void tracer::report_read_write_for_flags(tracee* process, int fd, unsigned long long flags) {
    if (fd < 0)
        return;
    int pid = process->get_pid();
    struct stat file_stat {};
    process->get_stat_for_fd(fd, &file_stat);
    std::string path = (std::string)process->get_path_for_fd(fd);

    flags &= O_ACCMODE;

    PS::TracerEventType event;

    if (flags == O_RDONLY) {
        event = PS::TRACER_EVENT_READ;
    } else if (flags == O_WRONLY) {
        event = PS::TRACER_EVENT_WRITE;
    } else if (flags == O_RDWR) {
        event = PS::TRACER_EVENT_READ_WRITE;
    } else {
        return;
    }

    report_file_op(event, pid, path, &file_stat);
}

void tracer::unlink_path(tracee* process, const std::string& path) {
    struct stat file_stat {};

    // Using lstat here as unlink does not resolve symlinks
    if (lstat(path.c_str(), &file_stat) < 0)
        return;

    bool is_inode_released = file_stat.st_nlink <= 1;
    bool is_unlink_successful = process->get_syscall_return_code() == 0;

    report_file_op(PS::TRACER_EVENT_UNLINK, process->get_pid(), path, &file_stat);

    if (is_inode_released && is_unlink_successful) {
        report_file_op(PS::TRACER_EVENT_INODE_RELEASE, process->get_pid(), "", &file_stat);
    }
}

void tracer::handle_unlink_syscall(tracee* process, const char* pathname) {
    std::filesystem::path filepath = process->get_cwd();
    filepath /= process->read_string(pathname);

    unlink_path(process, std::filesystem::weakly_canonical(filepath));
}

void tracer::handle_unlinkat_syscall(tracee* process, int dirfd, const char* pathname,
                                     int /*flag*/) {
    if (dirfd == AT_FDCWD) {
        handle_unlink_syscall(process, pathname);
        return;
    }

    // TODO: handle read_string failure
    std::filesystem::path filepath = process->get_path_for_fd(dirfd);
    filepath /= process->read_string(pathname);

    unlink_path(process, std::filesystem::weakly_canonical(filepath));
}

void tracer::handle_open_syscall(tracee* process, const char* /*pathname*/, int flags,
                                 mode_t /*mode*/) {
    report_read_write_for_flags(process, (int)process->get_syscall_return_code(), flags);
}

void tracer::handle_openat_syscall(tracee* process, int /*dirfd*/, const char* /*pathname*/,
                                   int flags, mode_t /*mode*/) {
    report_read_write_for_flags(process, (int)process->get_syscall_return_code(), flags);
}

void tracer::handle_openat2_syscall(tracee* process, int /*dirfd*/, const char* /*pathname*/,
                                    struct open_how* how, size_t /*size*/) {
    report_read_write_for_flags(process, (int)process->get_syscall_return_code(), how->flags);
}

void tracer::handle_creat_syscall(tracee* process, const char* /*pathname*/, mode_t /*mode*/) {
    report_read_write_for_flags(process, (int)process->get_syscall_return_code(),
                                O_WRONLY | O_CREAT | O_TRUNC);
}

void tracer::handle_mkdir_at_path(tracee* process, const std::string& path) {
    // Wait until process is out from syscall to call stat
    // on newly created directory.

    process->exit_from_syscall();
    struct stat file_stat {};

    if (stat(path.c_str(), &file_stat) < 0)
        return;

    report_file_op(PS::TRACER_EVENT_WRITE, process->get_pid(), path, &file_stat);
}

void tracer::handle_mkdir_syscall(tracee* process, const char* pathname, mode_t /*mode*/) {
    // TODO: handle read_string failure
    std::filesystem::path filepath = process->get_cwd();
    filepath /= process->read_string(pathname);

    // TODO: maybe move weakly_canonical into handle_mkdir_at_path method?
    handle_mkdir_at_path(process, std::filesystem::weakly_canonical(filepath));
}

void tracer::handle_mkdirat_syscall(tracee* process, int dirfd, const char* pathname, mode_t mode) {
    if (dirfd == AT_FDCWD) {
        handle_mkdir_syscall(process, pathname, mode);
        return;
    }

    // TODO: handle read_string failure
    std::filesystem::path filepath = process->get_path_for_fd(dirfd);
    filepath /= process->read_string(pathname);
    handle_mkdir_at_path(process, std::filesystem::weakly_canonical(filepath));
}

void tracer::handle_rmdir_syscall(tracee* process, const char* pathname) {
    std::filesystem::path filepath = process->get_cwd();
    filepath /= process->read_string(pathname);

    unlink_path(process, std::filesystem::weakly_canonical(filepath));
}

// Handle rename as unlink of destination
void tracer::handle_rename_syscall(tracee* process, const char* /*oldpath*/, const char* newpath) {
    handle_unlink_syscall(process, newpath);
}

void tracer::handle_renameat_syscall(tracee* process, int /*olddirfd*/, const char* /*oldpath*/,
                                     int newdirfd, const char* newpath) {
    handle_unlinkat_syscall(process, newdirfd, newpath, 0);
}

void tracer::handle_renameat2_syscall(tracee* process, int /*olddirfd*/, const char* /*oldpath*/,
                                      int newdirfd, const char* newpath, int flags) {
    if (flags & RENAME_NOREPLACE || flags & RENAME_EXCHANGE)
        return;

    handle_unlinkat_syscall(process, newdirfd, newpath, 0);
}

void tracer::handle_syscall(tracee* process) {
    struct user_regs_struct state = {};

    // Kill the process if architecture is not x86-64
    if (!process->ptrace_get_registers(&state)) {
        kill(process->get_pid(), SIGKILL);
        return;
    }

    uint64_t syscall_num = state.orig_rax;

    switch (syscall_num) {
    case SYS_open:
        handle_open_syscall(process, (char*)state.rdi, (int)state.rsi, state.rdx);
        break;
    case SYS_openat:
        handle_openat_syscall(process, (int)state.rdi, (char*)state.rsi, (int)state.rdx, state.r10);
        break;
    case SYS_openat2:
        handle_openat2_syscall(process, (int)state.rdi, (char*)state.rsi, (open_how*)state.rdx,
                               state.r10);
        break;
    case SYS_creat:
        handle_creat_syscall(process, (const char*)state.rdi, state.rsi);
        break;
    case SYS_unlink:
        handle_unlink_syscall(process, (char*)state.rdi);
        break;
    case SYS_unlinkat:
        handle_unlinkat_syscall(process, (int)state.rdi, (char*)state.rsi, (int)state.rdx);
        break;
    case SYS_rename:
        handle_rename_syscall(process, (char*)state.rdi, (char*)state.rsi);
        break;
    case SYS_renameat:
        handle_renameat_syscall(process, (int)state.rdi, (char*)state.rsi, (int)state.rdx,
                                (char*)state.r10);
        break;
    case SYS_renameat2:
        handle_renameat2_syscall(process, (int)state.rdi, (char*)state.rsi, (int)state.rdx,
                                 (char*)state.r10, (int)state.r11);
        break;
    case SYS_mkdir:
        handle_mkdir_syscall(process, (char*)state.rdi, (mode_t)state.rsi);
        break;
    case SYS_mkdirat:
        handle_mkdirat_syscall(process, (int)state.rdi, (char*)state.rsi, (mode_t)state.rdx);
        break;
    case SYS_rmdir:
        handle_rmdir_syscall(process, (char*)state.rdi);
        break;
    default:
        break;
    }
}

void tracer::handle_fork_clone(tracee* process) {
    pid_t forked_pid = (pid_t)process->ptrace_get_event_message();
    report_child(process->get_pid(), forked_pid);
}

/* MARK: Utilities */

void tracer::handle_possible_child(tracee* process) {
    if (process->stopped_at_fork_or_clone()) {
        handle_fork_clone(process);
    }
}

tracee* tracer::get_process(pid_t pid) {
    tracee* process = &processes[pid];
    if (!process->initialized())
        process->initialize(pid);
    return process;
}

tracee* tracer::wait_for_process() {
    int status = -1;
    pid_t pid = wait(&status);
    if (pid > 0) {
        tracee* process = get_process(pid);
        process->set_at_syscall_entry(status);
        return process;
    }
    return nullptr;
}
