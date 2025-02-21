// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace PS
{
class MakeProcess;

struct MakeGoal {
    std::string name;
    MakeProcess* make_process = nullptr;

    template <typename T>
    MakeGoal(T&& name, MakeProcess* make_process)
        : name(name), make_process(make_process) {}
};

} // namespace PS
