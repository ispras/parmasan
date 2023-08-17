#pragma once

#include "build-context.hpp"
#include "file-access-type.hpp"
#include "target-database.hpp"
#include "target.hpp"

namespace PS
{

struct AccessRecord {
    FileAccessType access_type{};
    BuildContext context;

    bool is_valid() const
    {
        return context.target != nullptr;
    }

    static AccessRecord invalid;
};

} // namespace PS
