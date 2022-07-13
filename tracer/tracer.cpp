
#include "tracer.hpp"
#include "tracee.hpp"

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

void tracer::report_read(pid_t pid, tracee_file* file) {
    fprintf(m_result_file, "R %d %lu:%lu\n", pid, file->m_dev, file->m_inode);
}

void tracer::report_write(pid_t pid, tracee_file* file) {
    fprintf(m_result_file, "W %d %lu:%lu\n", pid, file->m_dev, file->m_inode);
}

bool tracer::is_bpf_enabled() { return m_bpf_enabled; }

void tracer::parent_task() {
    wait(nullptr);

    if (m_bpf_enabled) {
        bpf_loop();
    } else {
        ptrace_loop();
    }
}

void tracer::bpf_loop() {
    ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, tracer::GENERAL_PTRACE_FLAGS | PTRACE_O_TRACESECCOMP);

    tracee* process = get_process(m_child_pid);
    process->ptrace_continue();

    while ((process = wait_for_process())) {
        if (process->stopped_at_seccomp()) {
            handle_syscall(process);
        } else {
        	handle_possible_fd_update(process);
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
        	handle_possible_fd_update(process);
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

    std::vector<unsigned int> syscalls_to_trace;

    syscalls_to_trace.push_back(__NR_write);
    syscalls_to_trace.push_back(__NR_read);

#ifdef DEBUG_FILE_PATHS
    syscalls_to_trace.push_back(__NR_open);
    syscalls_to_trace.push_back(__NR_openat);
#endif

    syscalls_to_trace.push_back(__NR_close);

#ifdef DEBUG
    printf("Syscalls filtered by BPF: ");
    for (unsigned syscall : syscalls_to_trace) {
        printf("%s ", SYS_NAMES[syscall]);
    }
    printf("\n");
#endif

    assert(seccomp_filter_syscalls(syscalls_to_trace));
}

/* MARK: Syscall handlers */

void tracer::handle_open_syscall(tracee* process,
                                 const char* pathname /*, int flags, mode_t mode*/) {
    process->report_file_open(process->get_syscall_return_code(), pathname);
}

void tracer::handle_openat_syscall(tracee* process, int dirfd,
                                   const char* pathname /*, int flags, mode_t mode*/) {
    process->report_file_open(process->get_syscall_return_code(), pathname);
}

void tracer::handle_close_syscall(tracee* process, int fd) { process->report_file_close(fd); }

void tracer::handle_write_syscall(tracee* process, int fd, char* buf, uint64_t len) {
    process->report_file_write(fd, len);
}

void tracer::handle_read_syscall(tracee* process, int fd, char* buf, uint64_t len) {
    process->report_file_read(fd, len);
}

void tracer::handle_syscall(tracee* process) {
    struct user_regs_struct state = {};
    process->ptrace_get_registers(&state);
    int syscall_num = state.orig_rax;

    switch (syscall_num) {
    case SYS_write:
        handle_write_syscall(process, (int)state.rdi, (char*)state.rsi, (uint64_t)state.rdx);
        break;
    case SYS_read:
        handle_read_syscall(process, (int)state.rdi, (char*)state.rsi, (uint64_t)state.rdx);
        break;
    case SYS_close:
        handle_close_syscall(process, (int)state.rdi);
        break;
#ifdef DEBUG_FILE_PATHS
    case SYS_open:
        handle_open_syscall(process, (char*)state.rdi);
        break;
    case SYS_openat:
        handle_openat_syscall(process, (int)state.rdi, (char*)state.rsi);
        break;
#endif
    default:
        break;
    }
}

void tracer::handle_fork_clone(tracee* process) {
    pid_t forked_pid = process->ptrace_get_event_message();
    printf("forked %d\n", forked_pid);
    tracee* forked_process = get_process(forked_pid);
    forked_process->inherit_opened_files_from(process);
}

/* MARK: Utilities */

void tracer::handle_possible_fd_update(tracee* process) {
	if (process->stopped_at_fork_or_clone()) {
        handle_fork_clone(process);
    } else if (process->stopped_at_exec()) {
    	
    	// File descriptor may be asked to close
    	// itself automatically when exec() ocurrs, so
    	// filter such ones from m_opened_files array

		process->filter_opened_files();
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
