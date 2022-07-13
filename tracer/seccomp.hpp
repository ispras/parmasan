#pragma once

#include <vector>

extern bool seccomp_filter_syscalls(const std::vector<unsigned int>& syscalls_to_trace);
extern bool seccomp_available();
