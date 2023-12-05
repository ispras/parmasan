
#include <fstream>
#include <unistd.h>
#include <getopt.h>
#include "parmasan-daemon.hpp"
#include "utils/run-shell.hpp"

// This class is a stub for a full-scale interface that is going to
// take its place further in this merge request.

class DummyDaemonDelegate : public PS::ParmasanDaemonDelegate
{
  public:
    explicit DummyDaemonDelegate(std::ofstream& stream)
        : m_stream(stream) {}
    void handle_race(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                     const PS::Race& race) override
    {
        m_stream << "race found at file '" << race.file->get_path() << "': ";
        m_stream << race.left_access.access_type << " at target '"
                 << race.left_access.context.target->name;
        m_stream << "', ";
        m_stream << race.right_access.access_type << " at target '"
                 << race.right_access.context.target->name;
        m_stream << "' are unordered\n";
    }

    void handle_access(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                       const PS::AccessRecord& access, const PS::File& file) override
    {
        // Do nothing, yet
    }

  private:
    std::ofstream& m_stream;
};

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
        {nullptr, 0, nullptr, 0}};

    const char* output_fname = "parmasan-dump.txt";
    PS::ParmasanInteractiveMode interactive_mode = PS::ParmasanInteractiveMode::NONE;
    std::ios_base::openmode mode = std::ofstream::out;
    int opt;
    while ((opt = getopt_long(argc, argv, "+ao:i::", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'a':
            mode |= std::ofstream::app;
            break;
        case 'o':
            output_fname = optarg;
            break;
        case 'i':
            if (optarg == nullptr || strcmp(optarg, "sync") == 0) {
                interactive_mode = PS::ParmasanInteractiveMode::SYNC;
            } else if (strcmp(optarg, "fast") == 0) {
                interactive_mode = PS::ParmasanInteractiveMode::FAST;
            } else if (strcmp(optarg, "none") == 0) {
                interactive_mode = PS::ParmasanInteractiveMode::NONE;
            } else {
                std::cerr << "Invalid argument for --interactive: " << optarg << "\n";
                return EXIT_FAILURE;
            }
            break;
        case '?':
        default:
            std::cerr << "Usage: " << argv[0] << " [--output OUTPUT] [--append]"
                                                 " [-i|-interactive [fast|sync|none]]"
                                                 " [-- COMMAND [ARGS...]]\n";
            return EXIT_FAILURE;
        }
    }

    std::ofstream dump_output_stream(output_fname, mode);
    DummyDaemonDelegate daemon_delegate(dump_output_stream);

    PS::ParmasanDaemon daemon;
    daemon.set_delegate(&daemon_delegate);
    daemon.set_interactive_mode(interactive_mode);

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
