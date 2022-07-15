
#include "tracee.hpp"
#include "tracer.hpp"
#include <dirent.h>
#include <linux/elf.h>
#include <sys/uio.h>
#include <cassert>

bool tracee::initialized() { return m_pid >= 0; }

void tracee::initialize(int pid, tracer* tracer) {
    assert(m_pid == -1 && pid != -1);
    m_pid = pid;
    m_tracer = tracer;
}

void tracee::set_at_syscall_entry(int status) {
    m_status = status;
    m_is_at_syscall_entry = true;
}

bool tracee::is_at_syscall_entry() { return m_is_at_syscall_entry; }

void tracee::exit_from_syscall() {
    if (!m_is_at_syscall_entry)
        return;

    ptrace_continue_to_syscall();
    wait();
}

int64_t tracee::get_syscall_return_code() {
    exit_from_syscall();
    if (!stopped_at_syscall()) {
        // Perhaps, it happened to be a faulty syscall
        // so the process got terminated
        return -1;
    }

    struct user_regs_struct state = {};
    ptrace_get_registers(&state);
    return state.rax;
}

bool tracee::stopped_at_fork_or_clone() {
    if (!WIFSTOPPED(m_status)) {
        return false;
    }

    int sig = m_status >> 8;

    return sig == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
           sig == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
           sig == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
}

bool tracee::stopped_at_exec() {
    if (!WIFSTOPPED(m_status)) {
        return false;
    }

    int sig = m_status >> 8;
    return sig == (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
}

bool tracee::stopped_at_seccomp() {
    return (m_status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) != 0;
}

bool tracee::stopped_at_syscall() {
    return WIFSTOPPED(m_status) && (WSTOPSIG(m_status) & 0x80) != 0;
}

bool tracee::stopped_at_signal() {
    if (!WIFSTOPPED(m_status)) {
        return false;
    }
    int sig = m_status >> 8;

    return (sig & ~0x7F) == 0;
}

unsigned long tracee::ptrace_get_event_message() {
    unsigned long result = 0;
    ptrace(PTRACE_GETEVENTMSG, m_pid, 0, &result);
    return result;
}

bool tracee::ptrace_get_registers(struct user_regs_struct* regs) {
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(*regs);

    ptrace(PTRACE_GETREGSET, m_pid, NT_PRSTATUS, &io);

    return io.iov_len == sizeof(*regs);
}

void tracee::ptrace_continue() { ptrace_continue_with_request(PTRACE_CONT); }

void tracee::ptrace_continue_to_syscall() { ptrace_continue_with_request(PTRACE_SYSCALL); }

void tracee::ptrace_continue_with_request(enum __ptrace_request request) {
    if (stopped_at_signal()) {
        ptrace(request, m_pid, 0, WSTOPSIG(m_status));
    } else {
        ptrace(request, m_pid, 0, 0);
    }

    m_status = -1;
    m_is_at_syscall_entry = false;
}

void tracee::ptrace_detach() {
    m_status = -1;
    m_is_at_syscall_entry = false;
    ptrace(PTRACE_DETACH, m_pid, 0, 0);
}

void tracee::wait() { waitpid(m_pid, &m_status, 0); }

void tracee::get_stat_for_fd(int fd, struct stat* file_stat) {
    std::stringstream stat_path_stream;

    stat_path_stream << "/proc/" << m_pid << "/fd/" << fd;
    std::string stat_path = stat_path_stream.str();

    stat(stat_path.c_str(), file_stat);
}

uint64_t tracee::read_word(void* process_addr) {
    uint64_t word = ptrace(PTRACE_PEEKTEXT, m_pid, process_addr, NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
        return 0;
    }
    return word;
}

int tracee::get_pid() { return m_pid; }

int tracee::get_status() { return m_status; }
