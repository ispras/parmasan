
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#define LONG_PATH_MAX (PATH_MAX * 4)

char buffer[LONG_PATH_MAX];

void seek_newline(FILE* file)
{
    while (true) {
        char c = fgetc(file);
        if (c == '\n' || c == EOF)
            break;
    }
}

void* read_loop(void* input)
{
    int fd = (uintptr_t)input;
    while (recv(fd, NULL, 0, MSG_TRUNC) > 0)
        ;
    return NULL;
}

int main(int argc, const char** argv)
{
    if (argc != 2) {
        printf("Usage: tracer-stub <log file path>\n");
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

    int fd = -1;
    if (sscanf(fd_str, "%d", &fd) != 1 || fd < 0) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable is invalid\n");
        return EXIT_FAILURE;
    }

    pthread_t read_loop_thread;
    pthread_create(&read_loop_thread, 0, &read_loop, (void*)(uintptr_t)fd);

    char child_to_daemon_prefix[] = "child -> daemon: ";
    char daemon_to_child_prefix[] = "daemon -> child: ";
    _Static_assert(sizeof(child_to_daemon_prefix) == sizeof(daemon_to_child_prefix),
                   "Prefixes should have the same length");

    int prefix_length = sizeof(child_to_daemon_prefix) - 1;

    while (fgets(buffer, prefix_length + 1, file)) {

        bool is_ctd = memcmp(buffer, child_to_daemon_prefix, prefix_length) == 0;
        bool is_dtc = !is_ctd && memcmp(buffer, daemon_to_child_prefix, prefix_length) == 0;

        int length = 0;
        if (is_ctd || is_dtc) {
            if (fscanf(file, "%d ", &length) != 1) {
                length = -1;
            }
        }

        if ((!is_ctd && !is_dtc) || length < 0) {
            // Recover by seeking the next line (to allow garbage lines in the log, i.e. comments)
            fseek(file, -1, SEEK_CUR);
            seek_newline(file);
            continue;
        }

        if (is_dtc) {
            // Skip the message altogether
            fseek(file, length, SEEK_CUR);
            seek_newline(file);
            continue;
        }

        if (length > LONG_PATH_MAX) {
            fprintf(stderr, "Message is too long (%d > %d)\n", length, LONG_PATH_MAX);

            // Skip the message altogether
            fseek(file, length, SEEK_CUR);
            seek_newline(file);
            continue;
        }

        fread(buffer, 1, length, file);

        seek_newline(file);

        write(fd, buffer, length);
    }

    return EXIT_SUCCESS;
}
