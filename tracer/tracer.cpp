
#include "tracer.hpp"

void tracer::trace(char* argv[]) {
	m_bpf_enabled = seccomp_available();
#ifdef DEBUG
	printf("Seccomp availability: %s\n", m_bpf_enabled ? "available" : "unavailable");
	if(!m_bpf_enabled) {
		printf("Falling back to PTRACE_SYSCALL tracing\n");
	}
#endif
	pid_t pid = fork();

    if(pid) {
    	m_child_pid = pid;
        parent_task();
    } else {
        child_task(argv);
    }
}

void tracer::report_read(int pid, ino_t inode) {
	fprintf(result_file, "R %d %lu\n", pid, inode);
}

void tracer::report_write(int pid, ino_t inode) {
	fprintf(result_file, "W %d %lu\n", pid, inode);
}

bool tracer::is_bpf_enabled() {
	return m_bpf_enabled;
}

void tracer::parent_task() {
	wait(nullptr);

	if(m_bpf_enabled) {
    	bpf_loop();
    } else {
    	ptrace_loop();
    }
}

void tracer::bpf_loop() {
	ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD);
	
	int status = 0;
	tracer_process* process = get_process(m_child_pid);
	process->ptrace_continue();

    while((process = wait_for_process())) {
		if (process->stopped_at_seccomp()) {
            handle_syscall(process);
        }

        process->ptrace_continue();
    }
}

void tracer::ptrace_loop() {
	ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, PTRACE_O_TRACESYSGOOD |
	                                        PTRACE_O_TRACEFORK |
	                                        PTRACE_O_TRACEVFORK |
	                                        PTRACE_O_TRACECLONE);
	int status = 0;
	tracer_process* process = get_process(m_child_pid);
	get_process(m_child_pid)->ptrace_continue_to_syscall();

    while((process = wait_for_process())) {
	    if (process->stopped_at_syscall()) {
	        handle_syscall(process);

	        // It's necessary to exit from syscall
	        // explicitly when in pure-ptrace mode,
	        // since otherwise some syscalls will
	        // end up being handled twice
	        process->exit_from_syscall();
	    }

        process->ptrace_continue_to_syscall();
    }
}

void tracer::child_task(char* argv[]) {
	ptrace(PTRACE_TRACEME, 0, 0, 0);

	if(m_bpf_enabled) {
		setup_seccomp();
	}

    execvp(argv[0], argv);
    perror("execvp");
}

void tracer::setup_seccomp() {

    std::vector<unsigned int> syscalls_to_trace;

    syscalls_to_trace.push_back(__NR_write);
    // syscalls_to_trace.push_back(__NR_read);

#ifdef DEBUG_FILE_PATHS
    // syscalls_to_trace.push_back(__NR_open);
    // syscalls_to_trace.push_back(__NR_openat);
#endif

    syscalls_to_trace.push_back(__NR_close);

#ifdef DEBUG
	printf("Syscalls filtered by BPF: ");
	for(unsigned syscall : syscalls_to_trace) {
		printf("%s ", SYS_NAMES[syscall]);
	}
	printf("\n");
#endif

    assert(seccomp_filter_syscalls(syscalls_to_trace));
}

/* MARK: Syscall handlers */

void tracer::handle_open_syscall(tracer_process* process, const char* pathname /*, int flags, mode_t mode*/) {
	process->report_file_open(process->get_syscall_return_code(), pathname);
}

void tracer::handle_openat_syscall(tracer_process* process, int dirfd, const char* pathname /*, int flags, mode_t mode*/) {
    process->report_file_open(process->get_syscall_return_code(), pathname);
}

void tracer::handle_close_syscall(tracer_process* process, int fd) {
	process->report_file_close(fd);
}

void tracer::handle_write_syscall(tracer_process* process, int fd, char* buf, uint64_t len) {
	process->report_file_write(fd, len);
}

void tracer::handle_read_syscall(tracer_process* process, int fd, char* buf, uint64_t len) {
    process->report_file_read(fd, len);
}

void tracer::handle_syscall(tracer_process* process) {
    struct user_regs_struct state = {};
    process->ptrace_get_registers(&state);
    int syscall_num = state.orig_rax;

    switch(syscall_num) {
    case SYS_write:
        handle_write_syscall (process, (int)   state.rdi, (char*) state.rsi, (uint64_t) state.rdx);
        break;
    case SYS_read:
        handle_read_syscall  (process, (int)   state.rdi, (char*) state.rsi, (uint64_t) state.rdx);
        break;
    case SYS_close:
    	handle_close_syscall (process, (int)   state.rdi);
    	break;
#ifdef DEBUG_FILE_PATHS
	case SYS_open:
        handle_open_syscall  (process, (char*) state.rdi);
        break;
    case SYS_openat:
        handle_openat_syscall(process, (int)   state.rdi, (char*) state.rsi);
        break;
#endif
    default:
        break;
    }
}

/* MARK: Utilities */

tracer_process* tracer::get_process(int pid) {
	tracer_process* process = &processes[pid];
    if(!process->initialized()) process->initialize(pid, this);
    return process;
}

tracer_process* tracer::wait_for_process() {
	int status = -1;
	int pid = wait(&status);
	if(pid > 0) {
		tracer_process* process = get_process(pid);
		process->set_at_syscall_entry(status);
		return process;
	}
	return nullptr;
}