#pragma once

#include <vector>

extern bool set_seccomp_filter(struct sock_fprog* prog);
extern bool seccomp_available();
