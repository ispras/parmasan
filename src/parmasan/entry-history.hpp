#pragma once

#include "access-record.hpp"
#include "file-access-type.hpp"
#include "target.hpp"
#include <vector>

namespace PS {

class File;

struct EntryData {
    std::vector<AccessRecord> accesses{};
    File* last_known_file;
};

} // namespace PS