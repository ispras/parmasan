// SPDX-License-Identifier: MIT

#pragma once

#include "access-record.hpp"
#include "file.hpp"

namespace PS
{
struct Race {
    File* file;
    const AccessRecord& left_access;
    const AccessRecord& right_access;
};

} // namespace PS
