#pragma once

#include <string>
#include <unordered_set>

namespace PS
{

class MakeProcess;

struct Target {
    Target(const Target& copy) = delete;
    Target(Target&& move) = default;

    explicit Target(std::string_view name, MakeProcess* database)
        : name(name), make_process(database) {}

    std::string name;
    std::unordered_set<Target*> dependents;
    unsigned long long last_traverse_num = 0;
    MakeProcess* make_process;
};

} // namespace PS
