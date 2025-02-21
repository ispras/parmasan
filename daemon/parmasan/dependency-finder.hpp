// SPDX-License-Identifier: MIT

#pragma once

#include <cassert>
#include <iostream>
#include <list>
#include <unordered_set>
#include <vector>
#include "access-record.hpp"

namespace PS
{

struct IDependencyFinder {
    virtual void push_access(AccessRecord access) = 0;
    virtual bool next() = 0;
    virtual const AccessRecord& get_left_access() = 0;
    virtual const AccessRecord& get_right_access() = 0;
    virtual bool is_required_dependency() = 0;

    static bool find_common_make_and_dependency(BuildContext a_ctx,
                                                BuildContext b_ctx);
};

// Assuming a single-threaded build, and based on the fact that the daemon receives packets
// in the order they are sent thanks to SOCK_SEQPACKET mode, the following can be stated.
//
// Let us assume that the file access pair access[i] and access[j], where i < j, forms a race.
// (In other words, that access pair is unordered, meaning that no directed path exists from
// access[i].target to access[j].target in the inverted dependency graph). Let there also be
// some accesses with indices i+1, i+2, ..., j-1 between access[i] and access[j]. Then there is
// at least one number k such that neighboring access[k] and access[k+1] will form a race.
//
// By contradiction, if this is not true and all access[k] and access[k+1] are ordered, then
// access[i] and access[j] will be ordered by induction.
//
// It follows from this statement that, for given conditions, it is sufficient to check only all
// pairs of neighboring accesses for ordering in order to prove that all pairs of file accesses
// are ordered.
//
// Critical access by definition must be performed strictly after all previous and before
// all subsequent accesses in the list. If an access may occur at any time between two
// consecutive critical accesses (for example, if it's a read access), it's not critical.
//
// CNDependencyFinder provides an API for searching all pairs of accesses that
// constitute potential race conditions: pairs of neighbouring critical accesses, and
// non-critical accesses coupled with critical ones nearest to them (to the left and to
// the right in the list). The user of the API might be interested in checking dependency
// relationship of Make targets corresponding to the accesses forming such pairs.
//
// In the example below, N is non-critical, C is critical access, and the lines mark
// pairs for checking. Note that interesting pairs have at least one critical access.
//
//   ┌─────┐
//   │ ┌─┬─┤ ┌─┐
//  -C-N-N-C-C-N-
//   └─┴─┘ └─┘
//
// The implementation searches the races on-line by remembering and iterating accesses
// between latest two critical accesses using a linked list.
// push_access(AccessRecord) and next() are O(1) amortized.

struct CNDependencyFinder : public IDependencyFinder {

    explicit CNDependencyFinder();

    virtual bool skip_access(const AccessRecord& /*record*/);

    virtual bool is_critical_access(const AccessRecord& /*access*/);

    void push_access(AccessRecord access) override;

    // Moves iterators to the next actual required dependency, or the next
    // potential required dependency.
    // Caller should check the is_required_dependency before calling next()
    // since push_access can influence whether the current access
    // pair form an actual required dependency.
    bool next() override;

    bool is_required_dependency() override;

    const AccessRecord& get_left_access() override
    {
        return *left_access;
    }

    const AccessRecord& get_right_access() override
    {
        return *right_access;
    }

  private:
    std::list<AccessRecord> last_accesses{};
    std::list<AccessRecord>::const_iterator left_access;
    std::list<AccessRecord>::const_iterator right_access;

    bool is_left_critical = false;
    bool is_right_critical = false;

    void trim_accesses();

    void left_next();

    void update_is_left_critical();

    void right_next();

    void update_is_right_critical();
};

struct DirLookupDependencyFinder : IDependencyFinder {
    void push_access(PS::AccessRecord access) override;

    bool next() override;

    bool is_required_dependency() override;

    const AccessRecord& get_left_access() override;

    const AccessRecord& get_right_access() override;

  private:
    AccessRecord initial_access = AccessRecord::invalid;
    AccessRecord dir_lookup = AccessRecord::invalid;
    std::unordered_set<BuildContext> write_targets;
};

// The entry-bound dependency finder is configured to ignore all the unlink
// operations. The reason behind it is that unlink events can lead to false
// positives if the inode has multiple file paths.
// Races with unlink operations are detected in path-bound race searching.

struct EntryBoundDependencyFinder : CNDependencyFinder {
    bool skip_access(const AccessRecord& access) override;
    bool is_critical_access(const AccessRecord& access) override;
};

struct PathBoundDependencyFinder : CNDependencyFinder {
    bool skip_access(const AccessRecord& access) override;
    bool is_critical_access(const AccessRecord& access) override;
};

} // namespace PS
