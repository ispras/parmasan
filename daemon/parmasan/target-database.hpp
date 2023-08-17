#pragma once

#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "access-record.hpp"
#include "build-context.hpp"
#include "make-goal.hpp"
#include "target.hpp"

namespace PS
{

class RaceSearchEngine;
class TargetDatabase
{
  public:
    explicit TargetDatabase() = default;

    bool read_target_pid_event(const char* buffer);
    bool read_dependency_event(const char* buffer);
    bool read_goal_event(const char* buffer);

    Target* get_target_for_name(const std::string& name);
    Target* get_target(pid_t pid) const;

    void set_parent_context(BuildContext parent_target);
    BuildContext get_parent_context() const;

    MakeGoal* get_current_goal() const;
    int get_depth() const;

  private:
    std::unordered_map<std::string, std::unique_ptr<Target>> m_targets_by_names;
    std::unordered_map<pid_t, Target*> m_target_by_pid_instances;

    BuildContext m_parent_context{};
    int m_depth = 0;
    std::vector<std::unique_ptr<MakeGoal>> m_goals;
};

} // namespace PS
