#pragma once

#include <string>
#include <unordered_set>

namespace PS
{

struct Target {
    Target(const Target& copy) = delete;
    Target(Target&& move) = default;

    template <typename T>
    explicit Target(T&& name)
        : name(std::forward<T>(name)) {}

    std::string name;
    std::unordered_set<Target*> dependents;
};

} // namespace PS
