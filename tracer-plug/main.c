
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LONG_PATH_MAX (PATH_MAX * 4)

char buffer[LONG_PATH_MAX];

int main(int argc, const char** argv)
{
    if (argc != 2) {
        printf("Usage: tracer-plug <log file path>\n");
        return EXIT_FAILURE;
    }

    const char* path = argv[1];
    FILE* file = fopen(path, "r");

    if (!file) {
        perror("Failed to open file\n");
        return EXIT_FAILURE;
    }

    char* fd_str = getenv("PARMASAN_DAEMON_FD");
    if (fd_str == NULL) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable not set\n");
        return EXIT_FAILURE;
    }

    int fd = atoi(fd_str);
    if (fd < 0) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable is invalid\n");
        return EXIT_FAILURE;
    }

    char* expected_prefix = "child -> daemon: ";
    unsigned int prefix_length = strlen(expected_prefix);

    while (fgets(buffer, LONG_PATH_MAX, file)) {

        if (memcmp(buffer, expected_prefix, prefix_length) == 0) {
            write(fd, buffer + prefix_length, strlen(buffer) - 1 - prefix_length);
        }
    }

    return EXIT_SUCCESS;
}
