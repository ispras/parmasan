#pragma once

#include "file-access-type.hpp"
#include "file.hpp"
#include "target.hpp"
#include <vector>

namespace PS {

struct EntryAccessRecord {
    FileAccessType access_type{};
    Target* target{};
};

struct EntryData {
    std::vector<EntryAccessRecord> accesses{};
    File* last_known_file;
};

} // namespace PS