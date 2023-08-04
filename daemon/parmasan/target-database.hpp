#pragma once

#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
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

    Target* get_target_for_name(const std::string& name);

    Target* get_target(pid_t pid);

    void reset();

  private:
    std::unordered_map<std::string, std::unique_ptr<Target>> m_targets_by_names;
    std::unordered_map<pid_t, Target*> m_target_by_pid_instances;
};

} // namespace PS
