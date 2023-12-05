#pragma once

#include "build-context.hpp"
#include "file-access-type.hpp"
#include "process.hpp"

namespace PS
{

struct AccessRecord {
    FileAccessType access_type{};
    BuildContext context;
    ProcessData* process;

    bool is_valid() const
    {
        return context.target != nullptr;
    }

    static AccessRecord invalid;
};

} // namespace PS
