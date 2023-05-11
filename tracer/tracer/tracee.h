#ifndef TRACEE_H
#define TRACEE_H

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
// #include <linux/openat2.h>
#include "openat2.h"

typedef struct tracee {
    int pid;
    int status;
} s_tracee;

/* MARK: Utilities */

// Lets the tracee continue until its current syscall is executed.
void tracee_exit_from_syscall(s_tracee* self);

// Returns the return code of the current syscall. This function should
// be called only if the tracee is stopped at a syscall.
unsigned long long int tracee_get_syscall_return_code(s_tracee* self);

// Returns true if the tracee was stopped at fork or clone.
bool tracee_stopped_at_fork_or_clone(s_tracee* self);

// Returns true if the tracee stopped at a seccomp event.
bool tracee_stopped_at_seccomp(s_tracee* self);

// Returns true if the tracee stopped at a syscall.
bool tracee_stopped_at_syscall(s_tracee* self);

// Returns true if the tracee was stopped by a signal.
bool tracee_stopped_at_signal(s_tracee* self);

// Returns the event message from the ptrace event.
unsigned long tracee_ptrace_get_event_message(s_tracee* self);

// Reads the registers of the tracee and stores them in the REGS structure.
bool tracee_ptrace_get_registers(s_tracee* self, struct user_regs_struct* regs);

// Lets the tracee continue until it reaches any seccomp event.
void tracee_ptrace_continue(s_tracee* self);

// Lets the tracee continue until it reaches a syscall or any seccomp event.
void tracee_ptrace_continue_to_syscall(s_tracee* self);

// Waits for this exact tracee to emit a signal.
void tracee_wait(s_tracee* self);

// Reads the path of the FD file descriptor into the PATH buffer. The PATH buffer
// must be at least PATH_MAX bytes long. Returns length of string on success, -1 on failure.
int tracee_get_path_for_fd(s_tracee* self, int fd, char* path, size_t path_size);

// Reads the cwd of the tracee to the PATH buffer. The buffer must be at least
// PATH_SIZE bytes long. returns length of the cwd. The contents are null-terminated.
// Returns length of string written to the buffer (excluding the null-terminator) on success, -1 on
// failure.
ssize_t tracee_get_cwd(s_tracee* self, char* path, size_t path_size);

// Reads a word (8 bytes on x86-64) from the tracee's memory in RESULT. Returns 0 on success.
int tracee_read_word(s_tracee* self, const void* process_addr, uint64_t* result);

// Reads a string from the tracee's memory at the PROCESS_ADDR address. The string is
// copied to the BUFFER. The BUFFER must be at least BUFFER_SIZE bytes long. The
// function returns the number of bytes read. The string is null-terminated.
int tracee_read_string(s_tracee* self, const char* process_addr, char* buffer, size_t buffer_size);

// Asks ptrace to let the tracee continue with the given REQUEST argument.
void tracee_ptrace_continue_with_request(s_tracee* self, enum __ptrace_request request);

#endif // TRACEE_H
