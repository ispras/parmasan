
#include <fstream>
#include <getopt.h>
#include "interface/parmasan-interface.hpp"
#include "options.hpp"
#include "parmasan/dumper.hpp"
#include "parmasan/inputs/file/file-data-source.hpp"
#include "parmasan/inputs/socket/socket-data-source.hpp"
#include "parmasan/parmasan-daemon.hpp"

int main(int argc, char** argv)
{
    if (getenv("PARMASAN_DAEMON_SOCK") != nullptr) {
        std::cerr << "Cannot start parmasan daemon from another parmasan daemon" << std::endl;
        return EXIT_FAILURE;
    }

    PS::Options options(argc, argv);

    if (!options.parse()) {
        return EXIT_FAILURE;
    }

    std::unique_ptr<PS::ParmasanDataSource> data_source{};

    if (options.o_input_fname) {
        // Use a dump file as an input with PS::ParmasanFileDataSource
        data_source = std::make_unique<PS::ParmasanFileDataSource>(options.o_input_fname);
    } else {
        // Run the build and start a socket with PS::ParmasanSocketDataSource
        auto socket_data_source = std::make_unique<PS::ParmasanSocketDataSource>();
        socket_data_source->set_build_args(argc - optind, argv + optind);
        socket_data_source->set_interactive_mode(options.o_interactive_mode);
        if (!socket_data_source->listen(options.o_socket_name, 1024)) {
            std::cerr << "Failed to listen the socket\n";
            return EXIT_FAILURE;
        }

        data_source = std::move(socket_data_source);
    }

    if (options.o_dump) {
        PS::ParmasanDumper dumper(options.o_output_fname, options.o_output_mode);
        data_source->set_delegate(&dumper);
        return data_source->loop() ? EXIT_SUCCESS : EXIT_FAILURE;
    } else {
        PS::ParmasanDaemon daemon;
        PS::ParmasanInterface interface;

        interface.set_output(options.o_output_fname, options.o_output_mode);
        daemon.set_delegate(&interface);
        daemon.set_interactive_mode(options.o_interactive_mode);
        data_source->set_delegate(&daemon);

        for (auto& breakpoint : options.o_breakpoints) {
            interface.add_breakpoint(breakpoint);
        }

        return data_source->loop() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}
