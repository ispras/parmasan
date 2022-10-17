#pragma once

#include <linux/types.h>
// #include <linux/openat2.h>

#define SYS_openat2 437
#define __NR_openat2 437

struct open_how {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};