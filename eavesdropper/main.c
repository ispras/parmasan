
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

int check_read_fd(const fd_set* mask, int readfd, int writefd, char buf[MAX_MESSAGE_SIZE],
                  const char* message)
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

    printf("%s: %.*s\n", message, n, buf);
    write(writefd, buf, n);
    return n;
}

int main(int argc, const char** argv)
{
    // Set stdout buffer to NULL to avoid buffering. This is needed to make sure
    // that the output is printed even if tracer or demon hangs.
    setbuf(stdout, NULL);

    int daemon_fd = atoi(getenv("PARMASAN_DAEMON_FD"));
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
        char daemon_fd_str[16] = {};
        sprintf(daemon_fd_str, "%d", socketpair_fds[1]);
        setenv("PARMASAN_DAEMON_FD", daemon_fd_str, 1);
        execvp(argv[1], (char* const*)argv + 1);
    } else {
        // Parent process

        // Setup SIGCHLD handling with use of signalfd
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);

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
            FD_SET(socketpair_fds[0], &read_fds);
            FD_SET(sigfd, &read_fds);

            if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0) {
                perror("select");
                break;
            }

            if (check_read_fd(&read_fds, socketpair_fds[0], daemon_fd, buf, "child -> daemon") < 0)
                break;

            if (check_read_fd(&read_fds, daemon_fd, socketpair_fds[0], buf, "daemon -> child") < 0)
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
}
