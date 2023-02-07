#pragma once

#include <vector>
#include "access-iterator.hpp"
#include "access-record.hpp"

namespace PS {

// Critical access by definition must be performed strictly after all previous and before
// all subsequent accesses in the list. If an access may occur at any time between two
// consecutive critical accesses (for example, if it's a read access), it's not critical.
//
// RequiredDependencyGenerator provides an API for iterating over all pairs of accesses that
// constitute potential race conditions: pairs of neighbouring critical accesses, and
// non-critical accesses coupled with critical ones nearest to them (to the left and to
// the right in the list). The user of the API might be interested in checking dependency
// relationship of Make targets corresponding to the accesses forming such pairs.
//
// In the example below, N is non-critical, C is critical access, and the lines mark
// pairs for checking. Note that interesting pairs have at least one critical access.
//
//     ┌─┬─┐ ┌─┐
//  -C-N-N-C-C-N-
//   └─┴─┘ └─┘
//
// The implementation iterates through all such pairs using two pointers in linear time.

template <typename CriticalAccessPredicate,
          typename SkipAccessPredicate = AccessIteratorFalsePredicate>
struct RequiredDependencyGenerator {

    AccessIterator<SkipAccessPredicate> left_access;
    AccessIterator<SkipAccessPredicate> right_access;
    bool is_left_critical = false;
    bool is_right_critical = false;

    explicit RequiredDependencyGenerator(const std::vector<AccessRecord>& records)
        : left_access(records), right_access(records) {
        update_is_left_critical();
        update_is_right_critical();
    }

    bool next() {
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

        // When we have only one critical access, move the other pointer.
        if (is_left_critical && !is_right_critical) {
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
            // If both of accesses happened to be critical,
            // move both of them. (They are guaranteed to be
            // neighbouring.)

            assert(left_access + 1 == right_access);

            left_next();
            right_next();
        }

        return static_cast<bool>(right_access);
    }

    void left_next() {
        left_access++;
        update_is_left_critical();
    }

    void update_is_left_critical() {
        is_left_critical = left_access && CriticalAccessPredicate()(*left_access);
    }

    void right_next() {
        right_access++;
        update_is_right_critical();
    }

    void update_is_right_critical() {
        is_right_critical = right_access && CriticalAccessPredicate()(*right_access);
    }
};

} // namespace PS