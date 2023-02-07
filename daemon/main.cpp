
#include "parmasan-daemon.hpp"
#include "utils/run-shell.hpp"
#include <unistd.h>

int main(int argc, char** argv)
{
    // Prevent daemon from running inside another daemon
    if (getenv("PARMASAN_DAEMON_FD") != nullptr) {
        std::cerr << "Cannot start parmasan daemon from another parmasan daemon" << std::endl;
        return EXIT_FAILURE;
    }

    std::ofstream dump_output_stream("parmasan-dump.txt");

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
        run_shell(argc - 1, argv + 1);
    }

    if(daemon.loop()) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
