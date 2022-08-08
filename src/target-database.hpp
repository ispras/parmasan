#pragma once

#include "file.hpp"
#include <fstream>
#include <string>
#include <vector>

namespace PS {

class Engine;
class TargetDatabase {
  public:
    explicit TargetDatabase(Engine* engine) : m_engine(engine) {}

    void read(std::ifstream&& stream);

    Target* get_target_for_name(const std::string& name) {
        auto it = m_targets_by_names.find(name);
        if(it == m_targets_by_names.end()) {
            std::unique_ptr<Target> target = std::make_unique<Target>(name);
            Target* result = target.get();
            m_targets_by_names[name] = std::move(target);
            return result;
        }
        return it->second.get();
    }

    Target* get_target_for(pid_t pid, int instance) {
        // Instance number is zero for the make process itself,
        // as it is never forked/cloned from any process in our
        // logs.
        if (instance < 1) {
            instance = 1;
        }
        auto it = m_target_by_pid_instances.find(pid);
        if (it == m_target_by_pid_instances.end())
            return nullptr;
        if (it->second.size() < instance)
            return nullptr;
        return it->second[instance - 1];
    }

  private:
    Engine* m_engine;

    std::unordered_map<std::string, std::unique_ptr<Target>> m_targets_by_names;
    std::unordered_map<pid_t, std::vector<Target*>> m_target_by_pid_instances;
};

} // namespace PS