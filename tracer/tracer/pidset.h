
#ifndef PARMASAN_PIDSET_H
#define PARMASAN_PIDSET_H

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pidlist {
    pid_t pid;
    struct pidlist* next;
} s_pidlist;

typedef struct pidset {
    s_pidlist* buffer;
    int capacity;
    int size;
} s_pidset;

bool pidset_create(struct pidset* set, int capacity);
void pidset_destroy(struct pidset* set);
bool pidset_add(struct pidset* set, pid_t pid);
void pidset_remove(struct pidset* set, pid_t pid);
bool pidset_contains(struct pidset* set, pid_t pid);

#ifdef __cplusplus
}
#endif

#endif // PARMASAN_PIDSET_H
