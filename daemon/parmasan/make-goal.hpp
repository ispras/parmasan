#pragma once

#include <string>

namespace PS
{
class TargetDatabase;

struct MakeGoal {
    std::string name;
    TargetDatabase* make_process = nullptr;

    template <typename T>
    MakeGoal(T&& name, TargetDatabase* make_process)
        : name(name), make_process(make_process) {}
};

} // namespace PS
