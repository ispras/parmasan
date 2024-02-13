#pragma once

#include "../../parmasan/parmasan-daemon.hpp"
#include "../../parmasan/tracer-process.hpp"
#include "helpers.hpp"
#include "parmasan/access-record.hpp"
#include "parmasan/file.hpp"
#include "parmasan/process.hpp"
#include "parmasan/race.hpp"

namespace PS
{

class ParmasanInterface;

enum class ParmasanStopReason {
    unknown,
    race,
    access
};

struct ParmasanStopContext {
    ParmasanStopReason reason;
    TracerProcess* tracer;
    union {
        struct {
            const Race* race;
        } race;
        struct {
            const File* file;
            const AccessRecord* access;
        } access;
    };
};

struct ParmasanInterfaceCommand {
    std::string name;
    std::string description;
    void (ParmasanInterface::*callback)(int argc, char** argv);
};

class ParmasanInterface : public ParmasanDaemonDelegate
{
  public:
    ParmasanInterface();

    void enter(ParmasanDaemon* daemon, const ParmasanStopContext& context);
    bool set_output(const char* filename, std::ios::openmode mode);

    void add_breakpoint(const BreakpointConfig& config);

  private:
    std::string get_command();

    void execute_user_command();
    void execute_argv(int argc, char** argv);
    void prompt();

    void cmd_help(int argc, char** argv);
    void cmd_quit(int argc, char** argv);
    void cmd_continue_execution(int argc, char** argv);
    void cmd_pidup(int argc, char** argv);
    void cmd_piddown(int argc, char** argv);
    void cmd_status(int argc, char** argv);
    void cmd_breakpoint(int argc, char** argv);
    void cmd_pid(int argc, char** argv);
    void cmd_targets(int argc, char** argv);

    void handle_race(ParmasanDaemon* daemon, TracerProcess* tracer, const Race& race) override;
    void handle_access(PS::ParmasanDaemon* daemon, PS::TracerProcess* tracer,
                       const AccessRecord& access, const File& file) override;

    bool m_stopped = false;
    const ParmasanStopContext* m_stop_context = nullptr;
    std::vector<ParmasanInterfaceCommand> m_commands{};

    PS::FilterSet break_filter;
    PS::FilterSet watch_filter;

    std::ofstream m_dump_output;
};

} // namespace PS
