
#include <assert.h>
#include <string.h>

size_t normalize_path(char* path)
{
    assert(path != NULL && path[0] == '/');

    int src_idx = 0;
    int dest_idx = 1;
    int dot_count = 0;

    do {
        src_idx++;
        if (path[src_idx] == '/' || path[src_idx] == '\0') {
            if (dot_count == 1) {
                src_idx++;
                dot_count = 0;
                continue;
            } else if (dot_count == 2) {
                dot_count = 0;
                dest_idx--;
                while (dest_idx > 0 && path[--dest_idx] != '/')
                    ;
            }

            if (path[dest_idx - 1] != '/') {
                path[dest_idx++] = '/';
            }
        } else if (path[src_idx] == '.') {
            dot_count++;
        } else {
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
