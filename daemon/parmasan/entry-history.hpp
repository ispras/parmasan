#pragma once

#include <list>
#include "dependency-finder.hpp"
#include "file.hpp"

namespace PS
{

struct EntryData {
    EntryBoundDependencyFinder dependency_finder;
    File* last_known_file;
};

} // namespace PS
