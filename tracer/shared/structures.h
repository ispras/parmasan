#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <assert.h>
#include <string.h>
#include <sys/types.h>

typedef struct entry {
    dev_t device; /* ID of device containing the file */
    ino_t inode;  /* File serial number */
} s_entry;

typedef enum parmasan_interactive_mode {
    PARMASAN_INTERACTIVE_NONE = 'N',
    PARMASAN_INTERACTIVE_FAST = 'F',
    PARMASAN_INTERACTIVE_SYNC = 'S'
} e_parmasan_interactive_mode;

typedef enum tracer_event_type {
    TRACER_EVENT_READ = 0,
    TRACER_EVENT_WRITE = 1,
    TRACER_EVENT_READ_WRITE = 2,
    TRACER_EVENT_UNLINK = 3,
    TRACER_EVENT_TOTAL_UNLINK = 4,
    TRACER_EVENT_CHILD = 5,
    TRACER_EVENT_DIE = 6
} e_tracer_event_type;

extern const char* TRACER_EVENT_CODES[];

typedef enum connection_state {
    CONNECTION_STATE_UNINITIALIZED = 0,
    CONNECTION_STATE_TRACER_PROCESS = 1,
    CONNECTION_STATE_MAKE_PROCESS = 2,
    CONNECTION_STATE_DONE = 3
} e_connection_state;

typedef struct tracer_child_event {
    pid_t pid;
    pid_t ppid;
} s_tracer_child_event;

typedef struct tracer_file_event {
    pid_t pid;
    s_entry file_entry;
} s_tracer_file_event;

#endif // STRUCTURES_H
