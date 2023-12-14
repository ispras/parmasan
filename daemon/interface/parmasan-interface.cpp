
#include "parmasan-interface.hpp"
#include <filesystem>
#include <getopt.h>
#include "helpers.hpp"

PS::ParmasanInterface::ParmasanInterface()
{
    m_commands.push_back(ParmasanInterfaceCommand{
        "help",
        "Print help message",
        &ParmasanInterface::cmd_help});
    m_commands.push_back(ParmasanInterfaceCommand{
        "quit",
        "Terminate current build (this will not terminate the daemon)",
        &ParmasanInterface::cmd_quit});
    m_commands.push_back(ParmasanInterfaceCommand{
        "continue",
        "Continue build upon next breakpoint",
        &ParmasanInterface::cmd_continue_execution});
    m_commands.push_back(ParmasanInterfaceCommand{
        "pidup",
        "Print the information about the specified process and its ancestors",
        &ParmasanInterface::cmd_pidup});
    m_commands.push_back(ParmasanInterfaceCommand{
        "piddown",
        "Print information about the specified process and its descendants",
        &ParmasanInterface::cmd_piddown});
    m_commands.push_back(ParmasanInterfaceCommand{
        "pid",
        "Print full information of the specific process",
        &ParmasanInterface::cmd_pid});
    m_commands.push_back(ParmasanInterfaceCommand{
        "status",
        "Print the stop reason, race information",
        &ParmasanInterface::cmd_status});
    m_commands.push_back(ParmasanInterfaceCommand{
        "break",
        "Break on event(s)",
        &ParmasanInterface::cmd_break});
    m_commands.push_back(ParmasanInterfaceCommand{
        "break-not",
        "Do not break on event(s)",
        &ParmasanInterface::cmd_break_not});
    m_commands.push_back(ParmasanInterfaceCommand{
        "watch",
        "Log event(s)",
        &ParmasanInterface::cmd_watch});
    m_commands.push_back(ParmasanInterfaceCommand{
        "watch-not",
        "Do not log event(s)",
        &ParmasanInterface::cmd_watch_not});
    m_commands.push_back(ParmasanInterfaceCommand{
        "targets",
        "Inspect makefile targets",
        &ParmasanInterface::cmd_targets});

    // By default, only trigger on races outside /dev/ directory
    break_filter.add_pattern("/dev/*", PatternFlags("R").invert());
    watch_filter.add_pattern("/dev/*", PatternFlags("R").invert());
}

void PS::ParmasanInterface::enter(PS::ParmasanDaemon* daemon,
                                  const PS::ParmasanStopContext& context)
{
    m_stopped = true;
    m_stop_context = &context;

    if (daemon->get_interactive_mode() == ParmasanInteractiveMode::FAST) {
        daemon->suspend_last_process();
    }

    while (m_stopped) {
        execute_user_command();
    }

    if (daemon->get_interactive_mode() == ParmasanInteractiveMode::FAST) {
        daemon->resume_last_process();
    }

    m_stop_context = nullptr;
}

static void trim(std::string& command)
{
    command.erase(command.begin(), std::find_if(command.begin(), command.end(), [](int ch) {
                      return !std::isspace(ch);
                  }));

    command.erase(std::find_if(command.rbegin(), command.rend(), [](int ch) {
                      return !std::isspace(ch);
                  }).base(),
                  command.end());
}

std::string PS::ParmasanInterface::get_command()
{
    std::string result;

    while (result.empty()) {
        prompt();
        std::getline(std::cin, result);
        trim(result);
    }

    return result;
}

void PS::ParmasanInterface::execute_user_command()
{
    std::vector<char*> argv;

    std::string command = get_command();
    char* parsed = command.data();
    argv.push_back(parsed);

    bool escape = false;

    for (char& c : command) {
        if (escape) {
            escape = false;
            *parsed = c;
            parsed++;
            continue;
        }
        if (c == '\\') {
            escape = true;
            continue;
        }
        if (c != ' ') {
            *parsed = c;
            parsed++;
            continue;
        }

        *parsed = '\0';
        parsed++;
        argv.push_back(parsed);
    }
    *parsed = '\0';

    execute_argv((int)argv.size(), argv.data());
}

void PS::ParmasanInterface::execute_argv(int argc, char** argv)
{
    std::vector<ParmasanInterfaceCommand*> matches;

    auto cmd = argv[0];
    auto cmdlen = strlen(argv[0]);

    for (auto& each_command : m_commands) {
        if (strncmp(each_command.name.c_str(), cmd, cmdlen) == 0) {
            if (cmdlen == each_command.name.size()) {
                // Exact match
                matches.clear();
                matches.push_back(&each_command);
                break;
            }
            matches.push_back(&each_command);
        }
    }

    if (matches.empty()) {
        std::cout << "command not found: " << argv[0] << "\n";
        return;
    }

    if (matches.size() > 1) {
        std::cout << "ambiguous command: ";
        for (size_t i = 0; i < matches.size(); i++) {
            if (i > 0) {
                std::cout << ", ";
            }
            std::cout << matches[i]->name;
        }
        std::cout << "\n";
        return;
    }

    argv[0] = matches[0]->name.data();

    (this->*(matches[0]->callback))(argc, argv);
}

void PS::ParmasanInterface::prompt()
{
    std::cout << "parmasan> ";
}

void PS::ParmasanInterface::cmd_help(int /* argc */, char** /* argv */)
{
    std::cout << "Available commands:\n";
    for (auto& command : m_commands) {
        std::cout << command.name << " - " << command.description << "\n";
    }
}

void PS::ParmasanInterface::cmd_quit(int /* argc */, char** /* argv */)
{
    m_stop_context->tracer->kill();
    m_stopped = false;
}

void PS::ParmasanInterface::cmd_continue_execution(int /* argc */, char** /* argv */)
{
    m_stopped = false;
}

void PS::ParmasanInterface::cmd_pidup(int argc, char** argv)
{
    bool make_only = false;
    PidSearchOpts opts{argc, argv};

    int option = 0;
    optind = 0;
    while ((option = getopt(argc, argv, "mlr")) != -1) {
        switch (option) {
        case 'l':
        case 'r':
        case '?':
        case ':':
            if (opts.option(option) < 0) {
                return;
            }
            break;
        case 'm':
            make_only = true;
            break;
        default:
            break;
        }
    }

    opts.read_pid_argument();

    if (!opts.is_sufficient_args()) {
        std::cout << "Usage: pidup [-m] <-l|-r|PID[.EPOCH]>\n";
        return;
    }

    PS::ProcessData* process = opts.find_process(m_stop_context);

    if (process) {
        ProcessPrinter(m_stop_context).print_process_parents(process, make_only);
    }
}

void PS::ParmasanInterface::cmd_piddown(int argc, char** argv)
{
    int option = 0;
    int depth = 3;
    bool make_only = false;
    PidSearchOpts opts{argc, argv};

    optind = 0;
    while ((option = getopt(argc, argv, "+md:alr")) != -1) {
        switch (option) {
        case 'a':
        case 'l':
        case 'r':
        case '?':
        case ':':
            if (opts.option(option) < 0) {
                return;
            }
            break;
        case 'm':
            make_only = true;
            break;
        case 'd':
            if (sscanf(optarg, "%d", &depth) != 1) {
                std::cout << "piddown: invalid depth: " << optarg << "\n";
                return;
            }
        default:
            break;
        }
    }

    opts.read_pid_argument();

    if (!opts.is_sufficient_args()) {
        std::cout << "Usage: piddown [-m] [-d DEPTH] <-l|-r|-a|PID[.EPOCH]>\n";
        return;
    }

    PS::ProcessData* process = opts.find_process(m_stop_context);

    if (!process)
        return;

    ProcessPrinter(m_stop_context).print_process_tree(process, depth, make_only);
}

void PS::ParmasanInterface::cmd_pid(int argc, char** argv)
{
    int option = 0;
    PidSearchOpts opts{argc, argv};

    optind = 0;
    while ((option = getopt(argc, argv, "+alr")) != -1) {
        switch (option) {
        case 'a':
        case 'l':
        case 'r':
        case '?':
        case ':':
            if (opts.option(option) < 0) {
                return;
            }
            break;
        default:
            break;
        }
    }

    opts.read_pid_argument();

    if (!opts.is_sufficient_args()) {
        std::cout << "Usage: pid <-l|-r|-a|PID[.EPOCH]>\n";
        return;
    }

    PS::ProcessData* process = opts.find_process(m_stop_context);

    if (!process) {
        return;
    }

    std::cout << "Process " << process->id.pid << "." << process->id.epoch << "\n";
    std::cout << " - Executable name: " << process->get_executable_name() << "\n";
    std::cout << " - Arguments:\n";

    int i = 0;
    for (const char* arg = process->get_argv_0(); arg; arg = process->get_next_arg(arg)) {
        std::cout << "   - argv[" << i << "] = " << arg << "\n";
        i++;
    }

    std::cout << " - Parent process: ";

    if (process->parent) {
        ProcessPrinter(m_stop_context).print_process(process->parent);
    } else {
        std::cout << "none\n";
    }

    std::cout << " - Child processes: ";

    if (!process->first_child) {
        std::cout << "none\n";
    } else {
        std::cout << "\n";
        for (PS::ProcessData* child = process->first_child; child; child = child->next_sibling) {
            std::cout << "   - ";
            ProcessPrinter(m_stop_context).print_process(child);
        }
    }

    std::cout << " - Is dead?         " << (process->dead ? "true" : "false") << "\n";
    std::cout << " - Is make process? " << (process->make_process ? "true" : "false") << "\n";

    std::cout << " - Nearest make process: ";

    auto make_process = process->get_make_process_data();

    if (make_process) {
        ProcessPrinter(m_stop_context).print_process(make_process);
        auto goal = make_process->make_process->get_current_goal();
        std::cout << " - Current goal: ";
        if (goal) {
            std::cout << goal->name << "\n";
        } else {
            std::cout << "none\n";
        }
    } else {
        std::cout << "none\n";
    }
}

void PS::ParmasanInterface::cmd_status(int /* argc */, char** /* argv */)
{
    if (m_stop_context->reason == ParmasanStopReason::race) {
        auto race = m_stop_context->race.race;
        auto file = race->file;
        auto access_a = race->left_access;
        auto access_b = race->right_access;

        std::cout << "Detected race:\n";
        std::cout << " - file: " << file->get_path() << "\n";
        std::cout << " - left access:  \n"
                  << "   - type:   " << access_a.access_type << "\n"
                  << "   - target: '" << access_a.context.target->name << "'\n"
                  << "   - goal:   '" << access_a.context.goal->name << "'\n"
                  << "   - process ";
        ProcessPrinter(m_stop_context).print_process(access_a.process);

        std::cout << " - right access: \n"
                  << "   - type:   " << access_b.access_type << "\n"
                  << "   - target  '" << access_b.context.target->name << "'\n"
                  << "   - goal    '" << access_b.context.goal->name << "'\n"
                  << "   - process ";
        ProcessPrinter(m_stop_context).print_process(access_b.process);
    } else if (m_stop_context->reason == ParmasanStopReason::access) {
        auto access = m_stop_context->access.access;
        auto file = m_stop_context->access.file;

        std::cout << "Stopped on file access:\n"
                  << " - file: " << file->get_path() << "\n"
                  << "   - type:   " << access->access_type << "\n"
                  << "   - target: '" << access->context.target->name << "'\n"
                  << "   - goal:   '" << access->context.goal->name << "'\n"
                  << "   - process ";

        ProcessPrinter(m_stop_context).print_process(access->process);
    } else {
        std::cout << "Stopped for unknown reason\n";
    }
}

void PS::ParmasanInterface::cmd_glob_generic(const char* command, int argc, char** argv,
                                             bool exclude, PS::FilterSet& filter_set)
{
    if (argc <= 1) {
        std::cout << "Usage: " << argv[0] << " BREAKPOINT [...BREAKPOINTS]\n";
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (!parse_glob_generic(argv[i], command, exclude, filter_set)) {
            break;
        }
    }
}

void PS::ParmasanInterface::cmd_break(int argc, char** argv)
{
    cmd_glob_generic("break ", argc, argv, false, break_filter);
}

void PS::ParmasanInterface::cmd_break_not(int argc, char** argv)
{
    cmd_glob_generic("break-not ", argc, argv, true, break_filter);
}

void PS::ParmasanInterface::cmd_watch(int argc, char** argv)
{
    cmd_glob_generic("watch ", argc, argv, false, watch_filter);
}

void PS::ParmasanInterface::cmd_watch_not(int argc, char** argv)
{
    cmd_glob_generic("watch-not ", argc, argv, true, watch_filter);
}

static void print_targets_for_process(const PS::ParmasanStopContext* ctx,
                                      PS::ProcessData* process, PS::GlobFilter& filter,
                                      int limit)
{
    if (!process->make_process) {
        std::cout << "Specified process is not make process\n";
        return;
    }

    bool printed_any = false;

    auto& targets = process->make_process->get_targets_by_names();
    for (auto& pair : targets) {
        auto& target = pair.second->name;

        if (filter.match(target)) {
            if (limit > 0) {
                if (!printed_any) {
                    std::cout << " - Targets for make process ";
                    PS::ProcessPrinter(ctx).print_process(process);
                    printed_any = true;
                }

                std::cout << "   - " << target << "\n";
            }
            limit--;
        }
    }

    if (limit < 0) {
        std::cout << "   - (... " << (-limit) << " more)\n";
    }
}

void PS::ParmasanInterface::cmd_targets(int argc, char** argv)
{
    int option = 0;
    PidSearchOpts opts{argc, argv};
    GlobFilter filter;
    bool filter_null = true;
    int limit = 10;

    optind = 0;
    while ((option = getopt(argc, argv, "+lrp:f:n:")) != -1) {
        switch (option) {
        case 'l':
        case 'r':
        case 'p':
        case '?':
        case ':':
            if (opts.option(option) < 0) {
                return;
            }
            break;
        case 'f':
            filter_null = false;
            filter.add_pattern(optarg, false, false);
            break;
        case 'n':
            if (sscanf(optarg, "%d", &limit) != 1) {
                std::cout << "Argument for -n must be a number\n";
                return;
            }
        default:
            break;
        }
    }

    if (filter_null) {
        filter.add_pattern("*", false, false);
    }

    if (limit <= 0) {
        return;
    }

    if (opts.is_sufficient_args()) {
        auto process = opts.find_process(m_stop_context);
        if (process) {
            print_targets_for_process(m_stop_context, process, filter, limit);
        }
    } else {
        auto& make_processes = m_stop_context->tracer->get_make_processes();
        for (auto& make_process : make_processes) {
            auto process = make_process->get_process_data();

            print_targets_for_process(m_stop_context, process, filter, limit);
        }
    }
}

bool PS::ParmasanInterface::handle_cli_command(int code, const char* command)
{
    switch (code) {
    case 'b':
        return parse_glob_generic(command, "--break=", false, break_filter);
    case 'B':
        return parse_glob_generic(command, "--break-not=", true, break_filter);
    case 'w':
        return parse_glob_generic(command, "--watch=", false, watch_filter);
    case 'W':
        return parse_glob_generic(command, "--watch-not=", true, watch_filter);
    default:
        assert(!"ParmasanInterface::handle_cli_command called with invalid code");
        return false;
    }
}

bool PS::ParmasanInterface::parse_glob_generic(const char* command, const char* type,
                                               bool exclude, PS::FilterSet& filter_set)
{
    auto colon = strchr(command, ':');
    const char* glob = colon + 1;

    if (!colon || *glob == '\0') {
        std::cout << "Breakpoint usage: " << type << "<[rwauR]:GLOB>\n";
        return false;
    }

    PatternFlags flags;

    if (exclude)
        flags.exclude();

    while (command != colon) {
        if (!flags.add_char(*command)) {
            std::cout << "Unrecognized flag for " << type << ": " << *command << "\n";
            return false;
        }
        command++;
    }

    // After all, this code is not that performance-critical...
    std::filesystem::path pattern_path;
    if (*glob == '/') {
        pattern_path = glob;
    } else {
        pattern_path = std::filesystem::current_path() / glob;
    }

    filter_set.add_pattern(pattern_path.lexically_normal().string(), flags);

    return true;
}

bool PS::ParmasanInterface::set_output(const char* filename, std::ios::openmode mode)
{
    m_dump_output.open(filename, mode);
    return (bool)m_dump_output;
}

void PS::ParmasanInterface::handle_race(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                                        const PS::Race& race)
{
    if (watch_filter.should_trigger_on_race(race)) {
        if (m_dump_output) {
            m_dump_output << "race found at file '" << race.file->get_path() << "': ";
            m_dump_output << race.left_access.access_type << " at target '"
                          << race.left_access.context.target->name;
            m_dump_output << "', ";
            m_dump_output << race.right_access.access_type << " at target '"
                          << race.right_access.context.target->name;
            m_dump_output << "' are unordered\n";
        }
    }

    if (daemon->get_interactive_mode() == ParmasanInteractiveMode::NONE) {
        return;
    }

    if (!break_filter.should_trigger_on_race(race)) {
        return;
    }

    ParmasanStopContext context{
        .reason = ParmasanStopReason::race,
        .tracer = tracer,
        .race = {
            .race = &race}};

    enter(daemon, context);
}

void PS::ParmasanInterface::handle_access(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                                          const PS::AccessRecord& access, const PS::File& file)
{
    if (watch_filter.should_trigger_on_access(access, file)) {
        if (m_dump_output) {
            m_dump_output << access.access_type << " to file " << file.get_path() << " at target '"
                          << access.context.target->name << "'\n";
        }
    }

    if (daemon->get_interactive_mode() == ParmasanInteractiveMode::NONE) {
        return;
    }

    if (!break_filter.should_trigger_on_access(access, file)) {
        return;
    }

    ParmasanStopContext context{
        .reason = ParmasanStopReason::access,
        .tracer = tracer,
        .access = {
            .file = &file,
            .access = &access}};

    enter(daemon, context);
}
