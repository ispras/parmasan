
#include <fstream>
#include <unistd.h>
#include <getopt.h>
#include "interface/parmasan-interface.hpp"
#include "parmasan-daemon.hpp"
#include "utils/run-shell.hpp"

int main(int argc, char** argv)
{
    // Prevent daemon from running inside another daemon
    if (getenv("PARMASAN_DAEMON_FD") != nullptr) {
        std::cerr << "Cannot start parmasan daemon from another parmasan daemon" << std::endl;
        return EXIT_FAILURE;
    }

    struct option long_options[] = {
        {"append", no_argument, nullptr, 'a'},
        {"output", required_argument, nullptr, 'o'},
        {"interactive", optional_argument, nullptr, 'i'},
        {"break", required_argument, nullptr, 'b'},
        {"break-not", required_argument, nullptr, 'B'},
        {"watch", required_argument, nullptr, 'w'},
        {"watch-not", required_argument, nullptr, 'W'},
        {nullptr, 0, nullptr, 0}};

    const char* output_fname = "parmasan-dump.txt";
    std::ios_base::openmode mode = std::ofstream::out;

    PS::ParmasanDaemon daemon;
    PS::ParmasanInterface interface;

    daemon.set_delegate(&interface);

    int opt;
    while ((opt = getopt_long(argc, argv, "+ab:B:w:W:o:i::", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'a':
            mode |= std::ofstream::app;
            break;
        case 'o':
            output_fname = optarg;
            break;
        case 'i':
            if (optarg == nullptr || strcmp(optarg, "sync") == 0) {
                daemon.set_interactive_mode(PS::ParmasanInteractiveMode::SYNC);
            } else if (strcmp(optarg, "fast") == 0) {
                daemon.set_interactive_mode(PS::ParmasanInteractiveMode::FAST);
            } else if (strcmp(optarg, "none") == 0) {
                daemon.set_interactive_mode(PS::ParmasanInteractiveMode::NONE);
            } else {
                std::cerr << "Invalid argument for --interactive: " << optarg
                          << ". Acceptable values are: sync, fast, none\n";
                return EXIT_FAILURE;
            }
            break;
        case 'b':
        case 'B':
        case 'w':
        case 'W':
            if (!interface.handle_cli_command(opt, optarg)) {
                return EXIT_FAILURE;
            }
            break;
        case '?':
        default:
            std::cerr << "Usage: " << argv[0] << " [-o | --output OUTPUT] [-a | --append]"
                                                 " [-i[MODE] | --interactive [MODE]]"
                                                 " [-b<BREAKPOINT> | --break=BREAKPOINT]"
                                                 " [-B<BREAKPOINT> | --break-not=BREAKPOINT]"
                                                 " [-w<BREAKPOINT> | --watch=BREAKPOINT]"
                                                 " [-W<BREAKPOINT> | --watch-not=BREAKPOINT]"
                                                 " [-- COMMAND [ARGS...]]\n";
            return EXIT_FAILURE;
        }
    }

    interface.set_output(output_fname, mode);

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

    if (fork() == 0) {
        PS::ParmasanDaemon::reset_signal_blocking();
        run_shell(argc - optind, argv + optind);
    }

    if (daemon.loop()) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
