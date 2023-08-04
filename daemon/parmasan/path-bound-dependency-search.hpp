#pragma once

#include "access-record.hpp"
#include "required-dependency-finder.hpp"

namespace PS::PathBoundDependencySearch
{

// To avoid duplicating reports from entry-bound dependency search, only races
// involving unlink operation are checked here

struct CriticalAccessPredicate {
    bool operator()(const AccessRecord& access)
    {
        return access.access_type == FileAccessType::unlink;
    }
};

struct DependencyFinder : RequiredDependencyFinder<CriticalAccessPredicate> {
};
} // namespace PS::PathBoundDependencySearch
