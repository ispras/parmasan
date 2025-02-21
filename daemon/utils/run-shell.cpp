// SPDX-License-Identifier: MIT

#include "run-shell.hpp"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

void __attribute__((__noreturn__)) run_shell(int argc, char* argv[])
{
    if (argc > 0) {
        execvp(argv[0], argv);
        perror(argv[0]);
        _Exit(EXIT_FAILURE);
    }

    const char* shell = getenv("SHELL");

    if (!shell) {
        shell = "/bin/sh";
    }

    execl(shell, shell, nullptr);

    perror(shell);
    _Exit(EXIT_FAILURE);
}
