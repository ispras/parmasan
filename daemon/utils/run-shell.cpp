
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include "run-shell.hpp"

void __attribute__((__noreturn__)) run_shell(int argc, char* argv[])
{
    if (argc > 0) {
        execvp(argv[0], argv);
        perror(argv[0]);
        _Exit(EXIT_FAILURE);
    }

    // Duplicate the argv array to add "-" as the first argument

    char argv0[] = "-";

    const char* shell = getenv("SHELL");

    if (!shell) {
        shell = "/bin/sh";
    }

    execl(shell, argv0, nullptr);

    perror(shell);
    _Exit(EXIT_FAILURE);
}