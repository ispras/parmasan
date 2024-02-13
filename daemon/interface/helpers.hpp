#pragma once

#include <iostream>
#include "globs.hpp"
#include "parmasan/access-record.hpp"
#include "parmasan/process.hpp"
#include "parmasan/race.hpp"
#include "utils/breakpoint-config.hpp"

namespace PS
{

struct ParmasanStopContext;

class ProcessPrinter
{
  public:
    ProcessPrinter(const ParmasanStopContext* stop_context)
        : m_stop_context(stop_context) {}

    void print_process_tree(ProcessData* process, int max_depth, bool make_only);
    void print_process(PS::ProcessData* process);
    void print_process_parents(ProcessData* process, bool make_only);

  private:
    void print_tree_recursive(ProcessData* process, int max_depth, bool make_only, int depth,
                              std::vector<bool>& tree_stack);

  private:
    const ParmasanStopContext* m_stop_context;
};

struct PidSearchOpts {
    pid_t pid = 0;
    unsigned int epoch = 0;

    bool pid_specified = false;
    bool epoch_specified = false;
    bool find_root = false;
    bool find_left = false;
    bool find_right = false;

    int argc = 0;
    char** argv = nullptr;

    PidSearchOpts(int argc, char** argv)
        : argc(argc), argv(argv)
    {
    }

    int option(int option);

    PS::ProcessData* find_process(const PS::ParmasanStopContext* context);

    int read_pid_argument();
    int read_pid_string(const char* pidstring);

    bool is_sufficient_args() const;
};

class GlobFilter
{
  public:
    GlobFilter& add_pattern(const std::string& pattern, bool is_inverted, bool is_and);

    bool match(std::string_view string);
    bool match(const PS::File& file);
    void ensure_valid();

  private:
    size_t match_file_rec(const PS::File& file, size_t state);

    Automaton m_automaton = Automaton::null();
    CompiledAutomaton m_compiled_automaton{};
    bool m_is_dirty = true;
};

class FilterSet
{
    GlobFilter read_filter;
    GlobFilter write_filter;
    GlobFilter access_filter;
    GlobFilter unlink_filter;
    GlobFilter race_filter;

  public:
    void add_pattern(const std::string& pattern, const BreakpointFlags& flags);
    bool should_trigger_on_race(const PS::Race& race);
    bool should_trigger_on_access(const AccessRecord& access, const PS::File& file);
};

} // namespace PS
