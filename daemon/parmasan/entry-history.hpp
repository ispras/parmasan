#pragma once

#include <vector>
#include "access-record.hpp"
#include "file-access-type.hpp"
#include "target.hpp"

namespace PS {

class File;

struct EntryData {
    std::vector<AccessRecord> accesses{};
    File* last_known_file;
};

} // namespace PS