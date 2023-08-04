#pragma once

#include "access-record.hpp"
#include "required-dependency-finder.hpp"

namespace PS::EntryBoundDependencySearch
{

// The entry-bound dependency finder is configured to ignore all the unlink
// operations. The reason behind it is that unlink events can lead to false
// positives if the inode has multiple file paths.
// Races with unlink operations are detected in path-bound race searching.

struct SkipPredicate {
    bool operator()(const AccessRecord& access)
    {
        return access.access_type == FileAccessType::unlink;
    }
};

// All access types except FileAccessType::read are marked as critical.

struct CriticalAccessPredicate {
    bool operator()(const AccessRecord& access)
    {
        return access.access_type != FileAccessType::read;
    }
};

struct DependencyFinder : RequiredDependencyFinder<CriticalAccessPredicate, SkipPredicate> {
};
} // namespace PS::EntryBoundDependencySearch
