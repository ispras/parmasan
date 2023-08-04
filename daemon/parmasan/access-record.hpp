#pragma once

#include "file-access-type.hpp"
#include "target.hpp"

namespace PS
{

struct AccessRecord {
    FileAccessType access_type{};
    Target* target{};

    bool is_valid() const
    {
        return target != nullptr;
    }

    static AccessRecord invalid;
};

} // namespace PS
