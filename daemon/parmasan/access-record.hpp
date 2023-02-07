#pragma once

#include "file-access-type.hpp"
#include "target.hpp"

namespace PS {

struct AccessRecord {
    FileAccessType access_type{};
    Target* target{};
};

} // namespace PS