#include "options.hpp"

const struct option PS::long_options[] = {
    {"append", no_argument, nullptr, 'a'},
    {"dump", no_argument, nullptr, 'd'},
    {"read", required_argument, nullptr, 'r'},
    {"output", required_argument, nullptr, 'o'},
    {"interactive", no_argument, nullptr, 'i'},
    {"break", required_argument, nullptr, 'b'},
    {"break-not", required_argument, nullptr, 'B'},
    {"watch", required_argument, nullptr, 'w'},
    {"watch-not", required_argument, nullptr, 'W'},
    {"socket", optional_argument, nullptr, 's'},
    {nullptr, 0, nullptr, 0}};

const char* PS::options_string = "+adr:b:B:w:W:o:i::";

bool PS::Options::parse()
{
    optind = 0;
    int opt = -1;

    while ((opt = getopt_long(m_argc, m_argv, options_string, long_options, nullptr)) != -1) {
        switch (opt) {
        case 'a':
            o_output_mode |= std::ofstream::app;
            break;
        case 'o':
            o_output_fname = optarg;
            break;
        case 's':
            o_socket_name = optarg;
            if (o_socket_name.empty()) {
                std::cerr << "Socket name cannot be empty\n";
                return false;
            }
            break;
        case 'd':
            o_dump = true;
            break;
        case 'r':
            o_input_fname = optarg;
            if (!o_input_fname || *o_input_fname == '\0') {
                std::cerr << "Input file name cannot be empty\n";
                return false;
            }
            break;
        case 'i':
            o_interactive_mode = PS::ParmasanInteractiveMode::SYNC;
            break;
        case 'b':
        case 'B':
        case 'w':
        case 'W':
            if (!store_breakpoint(opt, optarg)) {
                return false;
            }
            break;

        case '?':
            print_usage();
            return false;
        default:
            continue;
        }
    }

    return validate();
}

bool PS::Options::validate() const
{
    if (o_dump) {
        if (o_interactive_mode != PS::ParmasanInteractiveMode::NONE) {
            std::cerr << "Cannot use --dump with --interactive. Parmasan does not handle any "
                         "events when --dump is used.\n";
            return false;
        }

        if (!o_breakpoints.empty()) {
            std::cerr << "Breakpoints cannot be used with --dump. Parmasan does not handle "
                         "any events when --dump is used\n";
            return false;
        }
    }

    if (!o_breakpoints.empty() && o_interactive_mode == PS::ParmasanInteractiveMode::NONE) {
        std::cerr << "Breakpoints should be used with --interactive\n";
        return false;
    }

    return true;
}

bool PS::Options::store_breakpoint(int opt, const char* optarg)
{
    if (!optarg || *optarg == '\0') {
        std::cerr << "Breakpoint cannot not be empty\n";
        return false;
    }

    PS::BreakpointConfig breakpoint;

    if (!breakpoint.parse(optarg)) {
        std::cerr << "Failed to parse breakpoint: " << optarg << "\n"
                  << "Breakpoint syntax: <[rwauR]:GLOB>\n";
        return false;
    }

    if (tolower(opt) == 'b') {
        breakpoint.type = BreakpointType::BREAK;
    } else {
        breakpoint.type = BreakpointType::WATCH;
    }

    if (isupper(opt)) {
        breakpoint.flags.invert();
    }

    o_breakpoints.push_back(breakpoint);

    return true;
}

void PS::Options::print_usage()
{
    std::cerr << "Usage: " << m_argv[0] << " [-o | --output OUTPUT] [-a | --append]"
                                           " [-i[MODE] | --interactive [MODE]]"
                                           " [-d | --dump]"
                                           " [-r | --read INPUT]"
                                           " [-s | --socket SOCKET]"
                                           " [-b<BREAKPOINT> | --break=BREAKPOINT]"
                                           " [-B<BREAKPOINT> | --break-not=BREAKPOINT]"
                                           " [-w<BREAKPOINT> | --watch=BREAKPOINT]"
                                           " [-W<BREAKPOINT> | --watch-not=BREAKPOINT]"
                                           " [-- COMMAND [ARGS...]]\n";
}
