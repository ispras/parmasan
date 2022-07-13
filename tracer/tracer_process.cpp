
#include "tracer_process.hpp"
#include "tracer.hpp"

bool tracer_process::initialized() { return m_pid >= 0; }

void tracer_process::initialize(int pid, tracer* tracer) {
    assert(m_pid == -1 && pid != -1);
    m_pid = pid;
    m_tracer = tracer;
}

void tracer_process::set_at_syscall_entry(int status) {
    m_status = status;
    m_is_at_syscall_entry = true;
}

bool tracer_process::is_at_syscall_entry() { return m_is_at_syscall_entry; }

void tracer_process::report_file_open(int fd, const char* process_addr) {
    std::string name = read_string(process_addr);

    if (fd < 0) {
#ifdef DEBUG
        printf("[%d]: Failed to open file name=%s\n", m_pid, name.c_str());
#endif
        return;
    }

    ensure_fd_valid(fd);

    m_opened_files[fd] =
        tracer_process_file{std::move(name), get_inode_for_fd(fd), true, false, false};

#ifdef DEBUG
    printf("[%d]: Opened file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
}

void tracer_process::report_file_close(int fd) {
#ifdef DEBUG
    printf("[%d]: Closed file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
    if (get_file(fd)) {
        m_opened_files[fd] = tracer_process_file{{}, (ino_t)0, false, false, false};
    }
}

void tracer_process::report_file_read(int fd, uint64_t bytes) {
    tracer_process_file* file = ensure_file(fd);
#ifdef DEBUG
    printf("[%d]: Reading %lu bytes from ", m_pid, bytes);
    debug_file_info(fd);
    printf("\n");
#endif

    if (file->m_read_occurred)
        return;
    m_tracer->report_read(m_pid, file->m_inode);
    file->m_read_occurred = true;
}

void tracer_process::report_file_write(int fd, uint64_t bytes) {
    tracer_process_file* file = ensure_file(fd);
#ifdef DEBUG
    printf("[%d]: Writing %lu bytes to ", m_pid, bytes);
    debug_file_info(fd);
    printf("\n");
#endif

    if (file->m_write_occurred)
        return;
    m_tracer->report_write(m_pid, file->m_inode);
    file->m_write_occurred = true;
}

void tracer_process::exit_from_syscall() {
    if (!m_is_at_syscall_entry)
        return;

    ptrace_continue_to_syscall();
    wait();
}

int64_t tracer_process::get_syscall_return_code() {
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

tracer_process_file* tracer_process::get_file(int fd) {
    if (fd < m_opened_files.size() && m_opened_files[fd].m_opened) {
        return &m_opened_files[fd];
    }
    return nullptr;
}

bool tracer_process::exitted() { return WIFEXITED(m_status); }

bool tracer_process::stopped_at_seccomp() {
    return (m_status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) != 0;
}

bool tracer_process::stopped_at_syscall() {
    return WIFSTOPPED(m_status) && (WSTOPSIG(m_status) & 0x80) != 0;
}

bool tracer_process::stopped_at_signal() {
    if (!WIFSTOPPED(m_status)) {
        return false;
    }
    int sig = WSTOPSIG(m_status);
    if (sig & ~0x7F) {
        return false;
    }

    return sig != SIGTRAP && sig != SIGSTOP;
}

void tracer_process::ptrace_get_registers(struct user_regs_struct* regs) {
    ptrace(PTRACE_GETREGS, m_pid, 0, regs);
}

void tracer_process::ptrace_continue() {
    if (stopped_at_signal()) {
        ptrace(PTRACE_CONT, m_pid, 0, WSTOPSIG(m_status));
    } else {
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    }

    m_status = -1;
    m_is_at_syscall_entry = false;
}

void tracer_process::ptrace_continue_to_syscall() {
    if (stopped_at_signal()) {
        ptrace(PTRACE_SYSCALL, m_pid, 0, WSTOPSIG(m_status));
    } else {
        ptrace(PTRACE_SYSCALL, m_pid, nullptr, nullptr);
    }

    m_status = -1;
    m_is_at_syscall_entry = false;
}

void tracer_process::ptrace_detach() {
    m_status = -1;
    m_is_at_syscall_entry = false;
    ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr);
}

void tracer_process::wait() { waitpid(m_pid, &m_status, 0); }

tracer_process_file* tracer_process::ensure_file(int fd) {
    tracer_process_file* file = get_file(fd);
    if (!file) {
        return create_unnamed_file_for_fd(fd);
    }
    return file;
}

tracer_process_file* tracer_process::create_unnamed_file_for_fd(int fd) {
    ensure_fd_valid(fd);

    m_opened_files[fd] = tracer_process_file{{}, get_inode_for_fd(fd), true, false, false};

#ifdef DEBUG
    printf("[%d]: Implicitly opened file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
    return &m_opened_files[fd];
}

void tracer_process::debug_file_info(int fd) {
    tracer_process_file* file = get_file(fd);
    printf("fd=%d", fd);
    if (file) {
        printf(" inode=%lu", file->m_inode);
        if (!file->m_path.empty()) {
            printf(" path=%s", file->m_path.c_str());
        }
    }
}

void tracer_process::ensure_fd_valid(int fd) {
    int new_size = m_opened_files.size();

    while (fd >= new_size) {
        new_size = new_size * 2;
        if (new_size == 0)
            new_size = 1;
    }

    if (new_size == m_opened_files.size())
        return;

    m_opened_files.resize(new_size);
}

ino_t tracer_process::get_inode_for_fd(int fd) {
    struct stat file_stat {};
    std::stringstream stat_path_stream;

    stat_path_stream << "/proc/" << m_pid << "/fd/" << fd;
    std::string stat_path = stat_path_stream.str();

    stat(stat_path.c_str(), &file_stat);

    return file_stat.st_ino;
}

uint64_t tracer_process::read_word(void* process_addr) {
    uint64_t word = ptrace(PTRACE_PEEKTEXT, m_pid, process_addr, NULL);
    if (errno) {
        perror("PTRACE_PEEKTEXT");
        return 0;
    }
    return word;
}

std::string tracer_process::read_string(const char* process_addr) {
    uint64_t block_addr = (uint64_t)process_addr;
    unsigned char_index = (unsigned)(block_addr % 8);
    block_addr -= char_index;

    std::stringstream ss;

    while (true) {
        uint64_t process_word = read_word((void*)block_addr);
        const char* string_part = (const char*)&process_word + char_index;

        while (char_index++ < 8) {
            char next_character = *(string_part++);
            ss << next_character;

            if (next_character == '\0') {
                return ss.str();
            }
        }

        block_addr += 8;
        char_index = 0;
    }
}

int tracer_process::get_pid() { return m_pid; }

int tracer_process::get_status() { return m_status; }