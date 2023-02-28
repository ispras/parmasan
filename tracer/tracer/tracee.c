
#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include "tracee.h"

void tracee_exit_from_syscall(s_tracee* self)
{
    if (!self->status)
        return;

    tracee_ptrace_continue_to_syscall(self);
    tracee_wait(self);
}

unsigned long long int tracee_get_syscall_return_code(s_tracee* self)
{
    tracee_exit_from_syscall(self);
    if (!tracee_stopped_at_syscall(self)) {
        // Perhaps, it happened to be a faulty syscall
        // so the process got terminated
        return -1;
    }

    struct user_regs_struct state = {};
    tracee_ptrace_get_registers(self, &state);
    return state.rax;
}

bool tracee_stopped_at_fork_or_clone(s_tracee* self)
{
    if (!WIFSTOPPED(self->status)) {
        return false;
    }

    int sig = self->status >> 8;

    return sig == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
           sig == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
           sig == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
}

bool tracee_stopped_at_seccomp(s_tracee* self)
{
    return (self->status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) != 0;
}

bool tracee_stopped_at_syscall(s_tracee* self)
{
    return WIFSTOPPED(self->status) && (WSTOPSIG(self->status) & 0x80) != 0;
}

bool tracee_stopped_at_signal(s_tracee* self)
{
    if (!WIFSTOPPED(self->status)) {
        return false;
    }
    int sig = self->status >> 8;

    return (sig & ~0x7F) == 0;
}

unsigned long tracee_ptrace_get_event_message(s_tracee* self)
{
    unsigned long result = 0;
    ptrace(PTRACE_GETEVENTMSG, self->pid, 0, &result);
    return result;
}

bool tracee_ptrace_get_registers(s_tracee* self, struct user_regs_struct* regs)
{
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(*regs);

    ptrace(PTRACE_GETREGSET, self->pid, NT_PRSTATUS, &io);

    return io.iov_len == sizeof(*regs);
}

void tracee_ptrace_continue(s_tracee* self)
{
    tracee_ptrace_continue_with_request(self, PTRACE_CONT);
}

void tracee_ptrace_continue_to_syscall(s_tracee* self)
{
    tracee_ptrace_continue_with_request(self, PTRACE_SYSCALL);
}

void tracee_ptrace_continue_with_request(s_tracee* self, enum __ptrace_request request)
{
    if (tracee_stopped_at_signal(self)) {
        ptrace(request, self->pid, 0, WSTOPSIG(self->status));
    } else {
        ptrace(request, self->pid, 0, 0);
    }

    self->status = -1;
    self->status = false;
}

void tracee_wait(s_tracee* self)
{
    waitpid(self->pid, &self->status, 0);
}

void tracee_get_stat_for_fd(s_tracee* self, int fd, struct stat* file_stat)
{
    char cwd_path[128] = {0};
    sprintf(cwd_path, "/proc/%d/fd/%d", self->pid, fd);

    stat(cwd_path, file_stat);
}

int tracee_get_path_for_fd(s_tracee* self, int fd, char* path, size_t path_size)
{
    char fd_path[128] = {0};
    sprintf(fd_path, "/proc/%d/fd/%d", self->pid, fd);

    ssize_t size = readlink(fd_path, path, path_size - 1);
    if (size < 0) {
        return -1;
    }

    path[size] = '\0';

    return size;
}

ssize_t tracee_get_cwd(s_tracee* self, char* path, size_t path_size)
{
    char cwd_path[128] = {0};
    sprintf(cwd_path, "/proc/%d/cwd", self->pid);

    ssize_t size = readlink(cwd_path, path, path_size - 1);
    if (size < 0) {
        return -1;
    }

    path[size] = '\0';

    return size;
}

int tracee_read_word(s_tracee* self, const void* process_addr, uint64_t* result)
{
    *result = ptrace(PTRACE_PEEKTEXT, self->pid, process_addr, NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
    }
    return 0;
}

int tracee_read_string(s_tracee* self, const char* process_addr, char* buffer, size_t buffer_size)
{
    unsigned char_index = (unsigned)((uint64_t)(process_addr) % 8);
    const char* block_addr = process_addr - char_index;

    size_t characters_read = 0;

    // Null-terminate the buffer
    buffer[buffer_size - 1] = '\0';

    // The string is read in blocks of 8 bytes

    while (true) {
        uint64_t process_word = 0;
        if(tracee_read_word(self, block_addr, &process_word) < 0) {
            // Early-termination due to an error
            // Zero-terminate the buffer and return the number of characters read so far
            if (buffer_size > characters_read) {
                buffer[characters_read++] = '\0';
            }

            return characters_read;
        }
        const char* string_part = (const char*)(&process_word) + char_index;

        while (char_index++ < 8) {
            char next_character = *(string_part++);

            // If there is enough space in the buffer, copy the character
            if (buffer_size > characters_read) {
                buffer[characters_read] = next_character;
                characters_read++;
            } else {
                return (int)characters_read;
            }

            if (next_character == '\0') {
                // The end of the string has been reached, return the number of characters read
                return (int)characters_read;
            }
        }

        block_addr += 8;
        char_index = 0;
    }
}
