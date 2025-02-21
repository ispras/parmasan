// SPDX-License-Identifier: MIT

#pragma once

#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "access-record.hpp"
#include "build-context.hpp"
#include "make-goal.hpp"
#include "process.hpp"
#include "target.hpp"

namespace PS
{

class TracerProcess;
class MakeProcess
{
  public:
    explicit MakeProcess(TracerProcess* attached_tracer)
        : m_attached_tracer(attached_tracer) {};

    bool read_target_pid_event(const char* buffer);
    bool read_dependency_event(const char* buffer);
    bool read_goal_event(const char* buffer);

    Target* get_target_for_name(const std::string& name);
    Target* get_target_for_process(ProcessData* process) const;

    void set_parent_context(BuildContext parent_target);
    BuildContext get_parent_context() const;

    MakeGoal* get_current_goal() const;
    int get_depth() const;

    ProcessData* get_process_data() const;
    void set_process_data(ProcessData* process_data);

    const std::unordered_map<std::string, std::unique_ptr<Target>>& get_targets_by_names() const;

    bool search_for_dependency(Target* from, Target* to);

  private:
    bool search_for_dependency_rec(Target* from, Target* to);

    std::unordered_map<std::string, std::unique_ptr<Target>> m_targets_by_names;
    std::unordered_map<ProcessData*, Target*> m_target_by_process;

    TracerProcess* m_attached_tracer;
    BuildContext m_parent_context{};
    int m_depth = 0;
    std::vector<std::unique_ptr<MakeGoal>> m_goals;
    ProcessData* m_process_data;
    unsigned long long m_traverse_num = 0;
};

} // namespace PS
