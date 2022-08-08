#pragma once

#include <string>
#include <vector>

namespace PS {

class Target {
  public:
    std::string m_name;
    std::vector<Target*> m_dependents;

    Target(Target& copy) = delete;
    Target(Target&& move) = default;

    template <typename T>
    explicit Target(T&& name): m_name(std::forward<T>(name)) {

    }
};

}