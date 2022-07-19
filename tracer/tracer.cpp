
#include "tracer.hpp"
#include "tracee.hpp"
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <cassert>

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

void tracer::report_read(pid_t pid, struct stat* stat) {
    fprintf(m_result_file, "R %d %lu:%lu\n", pid, stat->st_dev, stat->st_ino);
}

void tracer::report_write(pid_t pid, struct stat* stat) {
    fprintf(m_result_file, "W %d %lu:%lu\n", pid, stat->st_dev, stat->st_ino);
}

void tracer::report_child(pid_t parent, pid_t child) {
    fprintf(m_result_file, "%d %d\n", parent, child);
}

bool tracer::is_bpf_enabled() { return m_bpf_enabled; }

void tracer::parent_task() {
    wait(nullptr);
    m_result_file = fopen(m_result_file_path, "w");
    if (!m_result_file) {
        perror("Failed to open result file");
        kill(m_child_pid, SIGKILL);
        printf("Aborting.\n");
        return;
    }

    if (m_bpf_enabled) {
        bpf_loop();
    } else {
        ptrace_loop();
    }

    fclose(m_result_file);
    m_result_file = nullptr;
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

void tracer::child_task(char* argv[]) {
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

void tracer::report_read_write_for_mode(tracee* process, int fd, mode_t mode) {
    if (fd < 0)
        return;
    int pid = process->get_pid();
    struct stat file_stat;
    process->get_stat_for_fd(fd, &file_stat);

    if ((mode | O_RDONLY) || (mode | O_RDWR))
        report_read(pid, &file_stat);
    if ((mode | O_WRONLY) || (mode | O_RDWR))
        report_write(pid, &file_stat);
}

void tracer::handle_open_syscall(tracee* process, const char* /*pathname*/, int /*flags*/, mode_t mode) {
    report_read_write_for_mode(process, process->get_syscall_return_code(), mode);
}

void tracer::handle_openat_syscall(tracee* process, int /*dirfd*/, const char* /*pathname*/, int /*flags*/,
                                   mode_t mode) {
    report_read_write_for_mode(process, process->get_syscall_return_code(), mode);
}

void tracer::handle_openat2_syscall(tracee* process, int /*dirfd*/, const char* /*pathname*/,
                                    struct open_how* how, size_t /*size*/) {
    report_read_write_for_mode(process, process->get_syscall_return_code(), how->mode);
}

void tracer::handle_creat_syscall(tracee* process, const char* /*pathname*/, mode_t mode) {
    report_read_write_for_mode(process, process->get_syscall_return_code(), mode);
}

void tracer::handle_syscall(tracee* process) {
    struct user_regs_struct state = {};

    // Kill the process if architecture is not x86-64
    if (!process->ptrace_get_registers(&state)) {
        kill(process->get_pid(), SIGKILL);
        return;
    }

    int syscall_num = state.orig_rax;

    switch (syscall_num) {
    case SYS_open:
        handle_open_syscall(process, (char*)state.rdi, (int)state.rsi, state.rdx);
        break;
    case SYS_openat:
        handle_openat_syscall(process, (int)state.rdi, (char*)state.rsi, state.rdx, state.rcx);
        break;
    case SYS_openat2:
        handle_openat2_syscall(process, (int)state.rdi, (char*)state.rsi, (open_how*)state.rdx,
                               state.rcx);
        break;
    case SYS_creat:
        handle_creat_syscall(process, (const char*)state.rdi, state.rsi);
        break;

    default:
        break;
    }
}

void tracer::handle_fork_clone(tracee* process) {
    pid_t forked_pid = process->ptrace_get_event_message();
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
        process->initialize(pid, this);
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
