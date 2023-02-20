
#include <fstream>
#include <unistd.h>
#include "parmasan-daemon.hpp"
#include "utils/run-shell.hpp"

int main(int argc, char** argv)
{
    // Prevent daemon from running inside another daemon
    if (getenv("PARMASAN_DAEMON_FD") != nullptr) {
        std::cerr << "Cannot start parmasan daemon from another parmasan daemon" << std::endl;
        return EXIT_FAILURE;
    }

    const char* output_fname = "parmasan-dump.txt";
    std::ios_base::openmode mode = std::ofstream::out;
    int opt;
    while ((opt = getopt(argc, argv, "+ao:")) != -1) {
        switch (opt) {
        case 'a':
            mode |= std::ofstream::app;
            break;
        case 'o':
            output_fname = optarg;
            break;
        case '?': default:
            std::cerr << "Usage: " << argv[0] <<
                    " [-o OUTPUT] [-a] [-- COMMAND [ARGS...]]\n";
            return EXIT_FAILURE;
        }
    }
    std::ofstream dump_output_stream(output_fname, mode);

    PS::ParmasanDaemon daemon(dump_output_stream);

    PS::ParmasanDaemon::setup_signal_blocking();

    int daemon_fd = daemon.setup();

    if (daemon_fd < 0) {
        std::cerr << "Failed to setup parmasan daemon\n";
        return EXIT_FAILURE;
    }

    // Set the environment variable so that the tracer can connect to the daemon

    char daemon_fd_str[16] = {};
    sprintf(daemon_fd_str, "%d", daemon_fd);
    setenv("PARMASAN_DAEMON_FD", daemon_fd_str, 1);

    // Run the specified script, or the "bash" command if argv[1] is not set

    std::cout << "Running daemon\n";

    if(fork() == 0) {
        PS::ParmasanDaemon::reset_signal_blocking();
        run_shell(argc - optind, argv + optind);
    }

    if(daemon.loop()) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
