// SPDX-License-Identifier: MIT

#pragma once

#include "build-context.hpp"
#include "file-access-type.hpp"
#include "process.hpp"

namespace PS
{

struct AccessRecord {
    FileAccessType access_type{};
    BuildContext context;
    ProcessData* process = nullptr;
    int return_code = 0;

    bool is_valid() const
    {
        return context.target != nullptr;
    }

    bool is_successful() const
    {
        return return_code >= 0;
    }

    static AccessRecord invalid;
};

} // namespace PS
