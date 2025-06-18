// SPDX-License-Identifier: MIT

#pragma once

#include "make-goal.hpp"

namespace PS
{

class Target;

struct BuildContext {
    Target* target = nullptr;

    BuildContext parent() const;
    int get_depth() const;
    void up_to_depth(int target_depth);

    explicit operator bool() const
    {
        return target != nullptr;
    }

    bool operator==(const BuildContext& other) const
    {
        return target == other.target;
    }
};

} // namespace PS

namespace std
{

template <>
struct hash<PS::BuildContext> {
    std::size_t operator()(const PS::BuildContext& key) const
    {
        return (std::hash<PS::Target*>()(key.target));
    }
};

} // namespace std
