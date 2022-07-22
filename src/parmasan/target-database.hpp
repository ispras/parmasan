#pragma once

#include "file.hpp"
#include "utils/buffer-reader.hpp"
#include <fstream>
#include <string>
#include <vector>

namespace PS {

class RaceSearchEngine;
class TargetDatabase {
  public:
    explicit TargetDatabase() = default;

    bool read_target_pid_event(BufferReader& reader);
    bool read_dependency_event(BufferReader& reader);

    Target* get_target_for_name(const std::string& name);

    Target* get_target(pid_t pid);

  private:
    std::unordered_map<std::string, std::unique_ptr<Target>> m_targets_by_names;
    std::unordered_map<pid_t, Target*> m_target_by_pid_instances;
};

} // namespace PS