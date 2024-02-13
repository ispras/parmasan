
#include "helpers.hpp"
#include <getopt.h>
#include "parmasan-interface.hpp"

void PS::ProcessPrinter::print_process_tree(PS::ProcessData* process, int max_depth,
                                            bool make_only)
{
    std::vector<bool> tree_stack;
    tree_stack.reserve(max_depth);
    print_tree_recursive(process, max_depth, make_only, 0, tree_stack);
}

void PS::ProcessPrinter::print_process(PS::ProcessData* process)
{
    if (process->cmd_line.empty()) {
        std::cout << "<unknown process> ";
    } else {
        std::cout << process->get_executable_name() << " ";
    }

    std::cout << "pid=" << process->id.pid << "." << process->id.epoch;

    auto context = m_stop_context->tracer->get_context_for_process(process);

    if (context.target) {
        std::cout << ", target=" << context.target->name;
    }

    if (process->dead) {
        std::cout << ", dead";
    }

    std::cout << "\n";
}

void PS::ProcessPrinter::print_process_parents(PS::ProcessData* process, bool make_only)
{
    while (process) {
        std::cout << " - ";
        print_process(process);

        do {
            process = process->parent;
        } while (process && make_only && !process->make_process);
    }
}

void PS::ProcessPrinter::print_tree_recursive(PS::ProcessData* process, int max_depth,
                                              bool make_only, int depth,
                                              std::vector<bool>& tree_stack)
{
    bool print = !make_only || process->make_process;
    if (print) {
        if (depth > max_depth)
            return;

        for (size_t i = 0; i < tree_stack.size(); i++) {
            if (i == tree_stack.size() - 1) {
                std::cout << (tree_stack[i] ? "├─" : "└─");
            } else {
                std::cout << (tree_stack[i] ? "│ " : "  ");
            }
        }

        print_process(process);
        depth++;
    }

    if (make_only && !process->make_process)
        return;

    assert(!process || process != process->first_child);

    tree_stack.push_back(false);
    for (auto child = process->first_child; child; child = child->next_sibling) {
        tree_stack.back() = child->next_sibling != nullptr;
        print_tree_recursive(child, max_depth, make_only, depth, tree_stack);
    }
    tree_stack.pop_back();
}

int PS::PidSearchOpts::option(int option)
{
    switch (option) {
    case 'a':
        find_root = true;
        return 0;
    case 'l':
        find_left = true;
        return 0;
    case 'r':
        find_right = true;
        return 0;
    case 'p':
        return read_pid_string(optarg);
    case ':':
    case '?':
    default:
        return -1;
    }
}

PS::ProcessData* PS::PidSearchOpts::find_process(const PS::ParmasanStopContext* context)
{
    if ((int)find_root + (int)find_left + (int)find_right > 1) {
        std::cout << "'a', 'l' and 'r' options are mutually exclusive\n";
    }

    if (find_root) {
        return context->tracer->get_alive_process(context->tracer->get_pid());
    }

    if (find_left) {
        if (context->reason != ParmasanStopReason::race) {
            std::cout << "'l' option only available in a race context\n";
            return nullptr;
        }
        return context->race.race->left_access.process;
    }

    if (find_right) {
        if (context->reason != ParmasanStopReason::race) {
            std::cout << "'r' option only available in a race context\n";
            return nullptr;
        }
        return context->race.race->right_access.process;
    }

    if (!epoch_specified) {
        epoch = context->tracer->get_pid_epoch(pid);
    }

    PS::ProcessData* process = context->tracer->get_process(pid, epoch);

    if (!process) {
        if (epoch_specified) {
            std::cout << argv[0] << ": process " << pid << " does not exist in epoch "
                      << epoch << "\n";
        } else {
            std::cout << argv[0] << ": process " << pid << " does not exist\n";
        }
    }

    return process;
}

int PS::PidSearchOpts::read_pid_argument()
{
    if (optind < argc) {
        return read_pid_string(argv[optind++]);
    }
    return 0;
}

int PS::PidSearchOpts::read_pid_string(const char* pidstring)
{
    int index = 0;
    if (sscanf(pidstring, "%d %n", &pid, &index) != 1) {
        std::cout << argv[0] << ": invalid pid: " << pidstring << "\n";
        return -1;
    }
    pidstring += index;
    pid_specified = true;

    if (*pidstring == '\0') {
        return 0;
    }

    if (*pidstring != '.') {
        std::cout << argv[0] << ": invalid pid format. Expected PID[.EPOCH]\n";
        return -1;
    }

    pidstring++;

    if (sscanf(pidstring, "%d", &epoch) != 1) {
        std::cout << argv[0] << ": invalid epoch: " << pidstring << "\n";
        return -1;
    }
    epoch_specified = true;
    return 0;
}

bool PS::PidSearchOpts::is_sufficient_args() const
{
    return pid_specified || find_root || find_left || find_right;
}

PS::GlobFilter& PS::GlobFilter::add_pattern(const std::string& pattern, bool is_inverted,
                                            bool is_and)
{
    Automaton new_automaton = Automaton::from_glob(pattern);
    if (is_inverted) {
        new_automaton.invert();
    }
    automaton_join(m_automaton, new_automaton, is_and);
    m_is_dirty = true;

    return *this;
}

void PS::GlobFilter::ensure_valid()
{
    if (m_is_dirty) {
        m_compiled_automaton = m_automaton.compile();
        m_is_dirty = false;
    }
}

bool PS::GlobFilter::match(std::string_view string)
{
    ensure_valid();
    size_t state = 0;
    auto& states = m_compiled_automaton.states;
    for (unsigned char c : string) {
        state = states[state].jump_table[c];
    }
    return states[state].is_final;
}

// To avoid constructing std::string to match a file path,
// separate efficient matching algorithm is implemented for PS::File.
bool PS::GlobFilter::match(const PS::File& file)
{
    ensure_valid();
    return m_compiled_automaton.states[match_file_rec(file, 0)].is_final;
}

size_t PS::GlobFilter::match_file_rec(const PS::File& file, size_t state)
{
    if (!file.m_parent) {
        // This is the root of the file system. Its name is always empty.
        return state;
    }

    state = match_file_rec(*file.m_parent, state);

    auto& states = m_compiled_automaton.states;
    state = states[state].jump_table[(unsigned char)'/'];

    for (unsigned char c : file.m_name) {
        state = states[state].jump_table[c];
    }

    return state;
}

void PS::FilterSet::add_pattern(const std::string& pattern, const PS::BreakpointFlags& flags)
{
    bool is_inverted = flags.inverted_bit;
    bool is_and = flags.and_bit;

    if (flags.read_bit)
        read_filter.add_pattern(pattern, is_inverted, is_and);

    if (flags.write_bit)
        write_filter.add_pattern(pattern, is_inverted, is_and);

    if (flags.access_bit)
        access_filter.add_pattern(pattern, is_inverted, is_and);

    if (flags.unlink_bit)
        unlink_filter.add_pattern(pattern, is_inverted, is_and);

    if (flags.race_bit)
        race_filter.add_pattern(pattern, is_inverted, is_and);
}

bool PS::FilterSet::should_trigger_on_race(const PS::Race& race)
{
    return race_filter.match(*race.file);
}

bool PS::FilterSet::should_trigger_on_access(const AccessRecord& access, const PS::File& file)
{
    switch (access.access_type) {
    case FileAccessType::read:
        return read_filter.match(file);
    case FileAccessType::write:
        return write_filter.match(file);
    case FileAccessType::read_write:
        return access_filter.match(file) || read_filter.match(file) || write_filter.match(file);
    case FileAccessType::unlink:
        return unlink_filter.match(file);
    default:
        return false;
    }
}
