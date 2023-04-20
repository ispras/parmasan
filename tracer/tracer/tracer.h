
#ifndef TRACER_H
#define TRACER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seccomp.h"
#include "shared/structures.h"
#include "tracee.h"

typedef struct tracer {
    int socket_fd;
    pid_t child_pid;
    bool bpf_enabled;
} s_tracer;

// The entry point of the tracer. This function starts a socket connection on SOCKET_PATH and
// forks a child process with given ARGV. This function is blocking and will return only when
// the child process exits and socket is closed.
void tracer_trace(char* argv[]);

// The parent job of the tracer. It connects to the socket and determines whether BPF should be
// used.
void tracer_parent_task(s_tracer* self);

// The main event loop of the tracer.
void tracer_bpf_loop(s_tracer* self);

// The fallback implementation of the tracer event loop. This function is used when BPF is not
// available or disabled.
void tracer_ptrace_loop(s_tracer* self);

// The child job of the tracer. It asks the kernel to start tracing the child process and executes
// the given ARGV.
void tracer_child_task(s_tracer* self, char* argv[]);

/* MARK: Syscall and fork handlers */

void tracer_report_read_write_for_flags(s_tracer* self, s_tracee* process, int fd,
                                        unsigned long long flags);
void tracer_handle_syscall(s_tracer* self, s_tracee* process);

void tracer_handle_fork_clone(s_tracer* self, s_tracee* process);
void tracer_handle_possible_child(s_tracer* self, s_tracee* process);

/* MARK: Socket methods */

// Setups the socket and sends the initial message to the daemon. Returns false on socket
// initialization failure.
bool tracer_connect_to_socket(s_tracer* self);

// Reports the file access on PATH with EVENT to the daemon. The STAT is used to determine
// the inode and device of the file. PATH should be an absolute canonical path.
void tracer_report_file_op(s_tracer* self, e_tracer_event_type event, pid_t pid, const char* path,
                           struct stat* stat);

// Reports the child process CHILD forked from PARENT.
void tracer_report_child(s_tracer* self, pid_t parent, pid_t child);

// Informs the daemon that the tracer is about to exit.
void tracer_report_done(s_tracer* self);

// Informs the daemon that the file on PATH was deleted. If the file does not have any
// hardlinks, the INODE_UNLINK event is also reported.
void tracer_unlink_path(s_tracer* self, s_tracee* process, const char* path);

// Waits for an acknowledgement message from the daemon. Returns 0 on success, or -1 if message is
// malformed.
int tracer_wait_for_parmasan_acknowledgement(s_tracer* self);

/* MARK: Utilities */

// Waits for any event from the child process. Writes the process pid and status into OUT_PROCESS.
int tracer_wait_for_process(s_tracee* out_process);

#ifdef __cplusplus
}
#endif

#endif // TRACER_H
