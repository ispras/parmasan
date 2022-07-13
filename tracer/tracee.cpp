
#include "tracee.hpp"
#include "tracer.hpp"
#include <dirent.h>

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

void tracee::report_file_open(int fd, const char* process_addr) {
    std::string name = read_string(process_addr);

    if (fd < 0) {
#ifdef DEBUG
        printf("[%d]: Failed to open file name=%s\n", m_pid, name.c_str());
#endif
        return;
    }

    ensure_fd_valid(fd);

    struct stat file_stat {};
    get_stat_for_fd(fd, &file_stat);
    m_opened_files[fd] = tracee_file(std::move(name), file_stat.st_ino, file_stat.st_dev);

#ifdef DEBUG
    printf("[%d]: Opened file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
}

void tracee::report_file_close(int fd) {
#ifdef DEBUG
    printf("[%d]: Closed file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
    if (get_file(fd)) {
        struct stat file_stat {};
        get_stat_for_fd(fd, &file_stat);
        m_opened_files[fd] = tracee_file();
    }
}

void tracee::report_file_read(int fd, uint64_t bytes) {
    tracee_file* file = ensure_file(fd);
#ifdef DEBUG
    printf("[%d]: Reading %lu bytes from ", m_pid, bytes);
    debug_file_info(fd);
    printf("\n");
#endif

    if (file->m_read_occurred)
        return;
    m_tracer->report_read(m_pid, file);
    file->m_read_occurred = true;
}

void tracee::report_file_write(int fd, uint64_t bytes) {
    tracee_file* file = ensure_file(fd);
#ifdef DEBUG
    printf("[%d]: Writing %lu bytes to ", m_pid, bytes);
    debug_file_info(fd);
    printf("\n");
#endif

    if (file->m_write_occurred)
        return;
    m_tracer->report_write(m_pid, file);
    file->m_write_occurred = true;
}

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

tracee_file* tracee::get_file(int fd) {
    if (fd < m_opened_files.size() && m_opened_files[fd].m_opened) {
        return &m_opened_files[fd];
    }
    return nullptr;
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
    if(!WIFSTOPPED(m_status)) {
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
    if (sig & ~0x7F) {
        return false;
    }

    return sig != SIGTRAP && sig != SIGSTOP;
}

unsigned long tracee::ptrace_get_event_message() {
    unsigned long result = 0;
    ptrace(PTRACE_GETEVENTMSG, m_pid, 0, &result);
    return result;
}

void tracee::ptrace_get_registers(struct user_regs_struct* regs) {
    ptrace(PTRACE_GETREGS, m_pid, 0, regs);
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

void tracee::inherit_opened_files_from(tracee* parent) {
    m_opened_files.resize(parent->m_opened_files.size());

    // Cannot use vector copy here, because it would also
    // copy m_read_ocurred and m_write_ocurred flags,
    // which are intended to be unset.

    for(int i = parent->m_opened_files.size() - 1; i >= 0; i--) {
        tracee_file* parent_file = &parent->m_opened_files[i];

        if(!parent_file->m_opened) continue;

        m_opened_files[i] = tracee_file(parent_file->m_path, parent_file->m_inode, parent_file->m_dev);
    }
}

void tracee::filter_opened_files() {
    std::stringstream stat_path_stream;

    stat_path_stream << "/proc/" << m_pid << "/fd";
    std::string stat_path = stat_path_stream.str();

    struct dirent *entry;
    DIR* dir = opendir(stat_path.c_str());

    if(!dir) return;

    for(tracee_file& file : m_opened_files) file.m_opened = false;

    while ((entry = readdir(dir)) != NULL) {
        char* end = NULL;
        int fd_index = strtol(entry->d_name, &end, 10);

        // Ensure that dir->d_name is a valid base-10 number
        if(*end != '\0') {
            continue;
        }
        
        ensure_file(fd_index)->m_opened = true;
    }
    closedir(dir);

#ifdef DEBUG_FILE_PATHS

    for(tracee_file& file : m_opened_files) {
        if(!file.m_opened && !file.m_path.empty) {
            file.m_path = {}
        }
    }

#endif
}

void tracee::wait() { waitpid(m_pid, &m_status, 0); }

tracee_file* tracee::ensure_file(int fd) {
    tracee_file* file = get_file(fd);
    if (!file) {
        return create_unnamed_file_for_fd(fd);
    }
    return file;
}

tracee_file* tracee::create_unnamed_file_for_fd(int fd) {
    ensure_fd_valid(fd);

    struct stat file_stat {};
    get_stat_for_fd(fd, &file_stat);
    m_opened_files[fd] = tracee_file(file_stat.st_ino, file_stat.st_dev);

#ifdef DEBUG
    printf("[%d]: Implicitly opened file ", m_pid);
    debug_file_info(fd);
    printf("\n");
#endif
    return &m_opened_files[fd];
}

void tracee::debug_file_info(int fd) {
    tracee_file* file = get_file(fd);
    printf("fd=%d", fd);
    if (file) {
        printf(" inode=%lu", file->m_inode);
        if (!file->m_path.empty()) {
            printf(" path=%s", file->m_path.c_str());
        }
    }
}

void tracee::ensure_fd_valid(int fd) {
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

std::string tracee::read_string(const char* process_addr) {
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

int tracee::get_pid() { return m_pid; }

int tracee::get_status() { return m_status; }
