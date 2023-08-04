#pragma once

#include <list>
#include "entry-bound-dependency-search.hpp"
#include "file.hpp"

namespace PS
{

struct EntryData {
    EntryBoundDependencySearch::DependencyFinder dependency_finder;
    File* last_known_file;
};

} // namespace PS
