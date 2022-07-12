#pragma once

#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include "syscalls.hpp"
#include "seccomp.hpp"
#include "tracer_process.hpp"

class tracer {
public:

	tracer(FILE* result_file): result_file(result_file) {}
    ~tracer() = default;
    tracer(const tracer& copy) = delete;
    tracer& operator=(const tracer& copy_assign) = delete;
    tracer(tracer&& move) = delete;
    tracer& operator=(tracer& move_assign) = delete;

	void trace(char* argv[]);

	void report_read(int pid, ino_t inode);
	void report_write(int pid, ino_t inode);

	bool is_bpf_enabled();

private:

	/* MARK: Private methods */

	void parent_task();
	void bpf_loop();
	void ptrace_loop();

	void child_task(char* argv[]);

	void setup_seccomp();

	/* MARK: Syscall handlers */

	void handle_open_syscall(tracer_process* process, const char* pathname /*, int flags, mode_t mode*/);
	void handle_openat_syscall(tracer_process* process, int dirfd, const char* pathname /*, int flags, mode_t mode*/);
	void handle_close_syscall(tracer_process* process, int fd);
	void handle_write_syscall(tracer_process* process, int fd, char* buf, uint64_t len);
	void handle_read_syscall(tracer_process* process, int fd, char* buf, uint64_t len);
	void handle_syscall(tracer_process* process);

	/* MARK: Utilities */

	tracer_process* get_process(int pid);
	tracer_process* wait_for_process();

	/* MARK: Private fields */

	FILE* result_file;
	int m_child_pid = -1;
	bool m_bpf_enabled = true;
	std::unordered_map<int, tracer_process> processes {};
};