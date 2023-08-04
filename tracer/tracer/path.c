
#include <assert.h>
#include <stdbool.h>
#include <string.h>

size_t normalize_path(char* path)
{
    assert(path != NULL && path[0] == '/');

    int src_idx = 0;
    int dest_idx = 1;
    int dot_count = 0;
    bool start = true;

    do {
        src_idx++;
        if (path[src_idx] == '/' || path[src_idx] == '\0') {
            start = true;
            if (dot_count == 1) {
                src_idx++;
                dot_count = 0;
                continue;
            } else if (dot_count == 2) {
                dot_count = 0;
                dest_idx--;
                while (dest_idx > 0 && path[--dest_idx] != '/')
                    ;
            } else if (dot_count > 2) {
                for (int i = 0; i < dot_count; i++) {
                    path[dest_idx++] = '.';
                }
                dot_count = 0;
            }

            if (dest_idx < 1 || path[dest_idx - 1] != '/') {
                path[dest_idx++] = '/';
            }
        } else if (path[src_idx] == '.' && start) {
            dot_count++;
        } else {
            for (int i = 0; i < dot_count; i++) {
                path[dest_idx++] = '.';
            }
            start = false;
            path[dest_idx++] = path[src_idx];
            dot_count = 0;
        }
    } while (path[src_idx] != '\0');

    if (dest_idx > 1 && path[dest_idx - 1] == '/') {
        dest_idx--;
    }

    path[dest_idx] = '\0';
    return dest_idx;
}
