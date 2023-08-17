#pragma once

#include "make-goal.hpp"

namespace PS
{

class Target;

struct BuildContext {
    Target* target = nullptr;
    MakeGoal* goal = nullptr;

    BuildContext parent() const;
    int get_depth() const;
    void up_to_depth(int target_depth);

    explicit operator bool() const
    {
        return target != nullptr;
    }
};

} // namespace PS
