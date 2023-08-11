#pragma once

#include <string>
#include <unordered_set>

namespace PS
{

class TargetDatabase;

struct Target {
    Target(const Target& copy) = delete;
    Target(Target&& move) = default;

    explicit Target(std::string_view name, TargetDatabase* database)
        : name(name), target_database(database) {}

    std::string name;
    std::unordered_set<Target*> dependents;
    unsigned long long last_traverse_num = 0;
    TargetDatabase* target_database;
};

} // namespace PS
