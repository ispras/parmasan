
#include "seccomp.hpp"
#include <cstddef>
#include <cstdio>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static bool set_filter(struct sock_fprog* prog) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0) {
        return false;
    }

    return true;
}

bool seccomp_filter_syscalls(const std::vector<unsigned int>& syscalls_to_trace) {

    std::vector<sock_filter> filter;

    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))));

    for (int i = syscalls_to_trace.size() - 1; i >= 0; i--) {
        filter.push_back(
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscalls_to_trace[i], (unsigned char)(i + 1), 0));
    }

    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    struct sock_fprog prog = {(unsigned short)filter.size(), filter.data()};
    return set_filter(&prog);
}

bool seccomp_available() {
#ifdef DISABLE_SECCOMP
    return false;
#else
    sock_filter filter[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};

    struct sock_fprog prog = {1, filter};

    return set_filter(&prog);
#endif
}
