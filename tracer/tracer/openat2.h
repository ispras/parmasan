#ifndef TRACER_OPENAT2_H
#define TRACER_OPENAT2_H

#include <linux/types.h>
// #include <linux/openat2.h>

#define SYS_openat2 437

struct open_how {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

#endif // TRACER_OPENAT2_H