
#include "seccomp.hpp"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

bool set_seccomp_filter(struct sock_fprog* prog) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0) {
        return false;
    }

    return true;
}

bool seccomp_available() {
#ifdef DISABLE_SECCOMP
    return false;
#else
    sock_filter filter[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};

    struct sock_fprog prog = {1, filter};

    return set_seccomp_filter(&prog);
#endif
}
