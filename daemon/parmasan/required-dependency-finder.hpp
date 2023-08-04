#pragma once

#include <cassert>
#include <iostream>
#include <vector>
#include "access-iterator.hpp"
#include "access-record.hpp"

namespace PS
{

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
// RequiredDependencyFinder provides an API for searching all pairs of accesses that
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

template <typename CriticalAccessPredicate,
          typename SkipAccessPredicate = AccessIteratorFalsePredicate>
struct RequiredDependencyFinder {

    explicit RequiredDependencyFinder()
        : last_accesses({AccessRecord::invalid}),
          left_access(last_accesses),
          right_access(last_accesses)
    {
    }

    void push_access(AccessRecord access)
    {
        // When new access is pushed to the list, and there is an
        // iterator pointing to the last element, its criticality
        // might change. So remember whether left or right
        // iterator was pointing to the last element.

        bool left_dirty = !left_access;
        bool right_dirty = !right_access;

        last_accesses.back() = access;
        last_accesses.push_back(AccessRecord::invalid);

        if (left_dirty) {
            left_access.skip_if_needed();
            update_is_left_critical();
        }
        if (right_dirty) {
            right_access.skip_if_needed();
            update_is_right_critical();
        }

        trim_accesses();
    }

    // Moves iterators to the next actual required dependency, or the next
    // potential required dependency.
    // Caller should check the is_required_dependency before calling next()
    // since push_access can influence whether the current access
    // pair form an actual required dependency.
    bool next()
    {
        // If we ran out of accesses, stop iterating.
        if (!right_access) {
            return false;
        }

        // If it's the first iteration.
        if (left_access == right_access) {

            if (is_left_critical) {
                // (C, N) or (C, C) case at the very start of the access list.
                right_next();
            } else {
                // (N, C) case.
                while (right_access && !is_right_critical) {
                    right_next();
                }
            }

            return static_cast<bool>(right_access);
        }

        if (!is_left_critical && !is_right_critical) {
            // The first dependency that is required to be checked is either
            // (C, N), (N, C) or (C, C) dependency. At least one of the accesses
            // is required to be critical. If the access stream starts with
            // several non-critical accesses, both of iterators may render
            // non-critical. (i.e, if the right iterator was at the end of the
            // last_accesses list, and new non-critical access was added to the
            // list, turning right iterator to be non-critical).
            // In this case, find the nearest critical access with right iterator,
            // if there is any

            while (!is_left_critical && !is_right_critical && right_access) {
                right_next();
            }
        } else if (is_left_critical && !is_right_critical) {
            // When we have only one critical access, move the other pointer.
            right_next();

            // If right access reached the next critical access,
            // the left access should be moved forward, as
            // it's unnecessary to check for dependency between
            // critical accesses when there are some non-critical
            // accesses between them.

            if (is_left_critical && is_right_critical) {
                left_next();
            }
        } else if (is_right_critical && !is_left_critical) {
            left_next();

            // If left iterator caught up the right one, move on to
            // the next section.
            if (left_access == right_access) {
                right_next();
            }
        } else if (is_left_critical && is_right_critical) {
            if (left_access + 1 == right_access) {
                // If both of accesses happened to be critical, and they
                // are neighbouring, move both of them
                left_next();
                right_next();
            } else {
                // Otherwise, there are some non-critical access between two,
                // which should be checked as well.
                left_next();
            }
        }

        return static_cast<bool>(right_access);
    }

    bool is_required_dependency()
    {
        return left_access && right_access && (is_left_critical || is_right_critical);
    }

    std::list<AccessRecord> last_accesses{};
    AccessIterator<SkipAccessPredicate> left_access;
    AccessIterator<SkipAccessPredicate> right_access;

  private:
    bool is_left_critical = false;
    bool is_right_critical = false;

    void trim_accesses()
    {
        while (last_accesses.begin() != left_access.position) {
            last_accesses.pop_front();
        }
    }

    void left_next()
    {
        left_access++;
        trim_accesses();
        update_is_left_critical();
    }

    void update_is_left_critical()
    {
        is_left_critical = left_access && CriticalAccessPredicate()(*left_access);
    }

    void right_next()
    {
        right_access++;
        update_is_right_critical();
    }

    void update_is_right_critical()
    {
        is_right_critical = right_access && CriticalAccessPredicate()(*right_access);
    }
};

} // namespace PS
