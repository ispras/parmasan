#ifndef SECCOMP_H
#define SECCOMP_H

#include <stdbool.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

bool set_seccomp_filter(struct sock_fprog* prog);
bool seccomp_available();

#endif // SECCOMP_H