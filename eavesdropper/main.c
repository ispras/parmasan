
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/signal.h>
#include <sys/signalfd.h>

#define MAX_MESSAGE_SIZE (PATH_MAX * 4)

static int move_fd_above(int fd, int limit)
{
    if (fd > limit || fd < 0) {
        return fd;
    }

    int result = move_fd_above(dup(fd), limit);
    close(fd);

    return result;
}

int check_read_fd(FILE* output, const fd_set* mask, int readfd, int writefd,
                  char buf[MAX_MESSAGE_SIZE], const char* message)
{
    if (!FD_ISSET(readfd, mask))
        return 0;

    int n = read(readfd, buf, MAX_MESSAGE_SIZE);

    if (n < 0) {
        perror("read");
    }

    if (n <= 0) {
        return -1;
    }

    if (!output) {
        output = stdout;
    }

    fprintf(output, "%s: %10u ", message, n);
    fwrite(buf, 1, n, output);
    fprintf(output, "\n");
    write(writefd, buf, n);
    return n;
}

int main(int argc, char** argv)
{
    FILE* output = NULL;
    int opt = 0;
    while ((opt = getopt(argc, argv, "+o:")) != -1) {
        switch (opt) {
        case 'o':
            output = fopen(optarg, "w");
            if (!output) {
                perror("Could not open the output file");
                return EXIT_FAILURE;
            }
            break;
        case '?':
        default:
            fprintf(stderr, "Usage: %s [-o OUTPUT] [--] COMMAND [ARGS...]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind == argc) {
        fprintf(stderr, "Please, specify command to eavesdrop\n");
        return EXIT_FAILURE;
    }

    // Set stdout buffer to NULL to avoid buffering. This is needed to make sure
    // that the output is printed even if tracer or demon hangs.
    setbuf(stdout, NULL);

    // Read environment variable "PARMASAN_DAEMON_FD" to get the socket file descriptor
    char* daemon_fd_str = getenv("PARMASAN_DAEMON_FD");
    if (daemon_fd_str == NULL) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable not set\n");
        return false;
    }

    int daemon_fd = -1;
    if (sscanf(daemon_fd_str, "%d", &daemon_fd) != 1 || daemon_fd < 0) {
        fprintf(stderr, "PARMASAN_DAEMON_FD environment variable is invalid\n");
        return false;
    }

    int socketpair_fds[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socketpair_fds);

    // Sometimes GNU configure (and other shell scripts) can override
    // file descriptors without checking whether it was already taken.
    // Shell scripts can only use single-digit file descriptors, so
    // here the exposed file descriptor is moved above 9 to avoid
    // some possible collisions.
    socketpair_fds[1] = move_fd_above(socketpair_fds[1], 9);

    // Check that fd is valid
    if (fcntl(daemon_fd, F_GETFD) == -1) {
        perror("fcntl");
        return EXIT_FAILURE;
    }

    if (fork() == 0) {
        // Child process
        char patched_daemon_fd_str[16] = {};
        sprintf(patched_daemon_fd_str, "%d", socketpair_fds[1]);
        setenv("PARMASAN_DAEMON_FD", patched_daemon_fd_str, 1);
        execvp(argv[optind], argv + optind);
        perror("execvp");
        return EXIT_FAILURE;
    } else {
        // Parent process

        // Setup SIGCHLD handling with use of signalfd
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        int child_fd = socketpair_fds[0];

        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
            perror("sigprocmask");
            return false;
        }

        int sigfd = signalfd(-1, &mask, 0);

        char buf[MAX_MESSAGE_SIZE] = {};

        while (true) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(daemon_fd, &read_fds);
            FD_SET(child_fd, &read_fds);
            FD_SET(sigfd, &read_fds);

            if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0) {
                perror("select");
                break;
            }

            if (check_read_fd(output, &read_fds, child_fd, daemon_fd, buf, "child -> daemon") < 0)
                break;

            if (check_read_fd(output, &read_fds, daemon_fd, child_fd, buf, "daemon -> child") < 0)
                break;

            if (FD_ISSET(sigfd, &read_fds)) {
                struct signalfd_siginfo fdsi;
                read(sigfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (fdsi.ssi_signo == SIGCHLD) {
                    break;
                }
            }
        }

        close(sigfd);
    }

    close(socketpair_fds[0]);
    close(socketpair_fds[1]);
    if (output) {
        fclose(output);
    }
}
