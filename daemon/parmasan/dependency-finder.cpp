
#include "dependency-finder.hpp"
#include "make-process.hpp"
#include "target.hpp"

bool PS::IDependencyFinder::find_common_make_and_dependency(BuildContext a_ctx,
                                                            BuildContext b_ctx)
{
    // It's not required to call search_for_dependency on the entire target chain, since
    // if two targets are the same level and from the same makefile, they must have the same
    // parent target. So search_for_dependency is only called for the deepest pair of targets
    // sharing the same target database.

    // Balance depths.

    a_ctx.up_to_depth(b_ctx.get_depth());
    b_ctx.up_to_depth(a_ctx.get_depth());

    // Go up the target chain until target databases match.

    while (a_ctx && b_ctx && a_ctx.target->make_process != b_ctx.target->make_process) {
        a_ctx = a_ctx.parent();
        b_ctx = b_ctx.parent();
    }

    // Finally, check if these two targets depend on each other.

    if (a_ctx && b_ctx) {
        auto make_process = a_ctx.target->make_process;
        return make_process->search_for_dependency(a_ctx.target, b_ctx.target);
    }

    // This might occur if the root makefile re-executed itself.
    // In this case, parmasan considers that the new re-executed process
    // is a sibling of the old make process with the same parent target.
    // But if the make process. didn't have any parent target, its sibling
    // won't have it as well. In this case, targets are considered
    // to be dependent.
    return true;
}

PS::CNDependencyFinder::CNDependencyFinder()
    : last_accesses({AccessRecord::invalid}),
      left_access(last_accesses.begin()),
      right_access(last_accesses.begin())
{
}

bool PS::CNDependencyFinder::skip_access(const AccessRecord&)
{
    return false;
}

bool PS::CNDependencyFinder::is_critical_access(const AccessRecord&)
{
    return false;
}

void PS::CNDependencyFinder::push_access(AccessRecord access)
{
    if (skip_access(access)) {
        return;
    }

    // When new access is pushed to the list, and there is an
    // iterator pointing to the last element, its criticality
    // might change. So remember whether left or right
    // iterator was pointing to the last element.

    bool left_dirty = !left_access->is_valid();
    bool right_dirty = !right_access->is_valid();

    last_accesses.back() = access;
    last_accesses.push_back(AccessRecord::invalid);

    if (left_dirty) {
        update_is_left_critical();
    }
    if (right_dirty) {
        update_is_right_critical();
    }

    trim_accesses();
}

bool PS::CNDependencyFinder::next()
{
    // If we ran out of accesses, stop iterating.
    if (!right_access->is_valid()) {
        return false;
    }

    // If it's the first iteration.
    if (left_access == right_access) {

        if (is_left_critical) {
            // (C, N) or (C, C) case at the very start of the access list.
            right_next();
        } else {
            // (N, C) case.
            while (right_access->is_valid() && !is_right_critical) {
                right_next();
            }
        }

        return right_access->is_valid();
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

        while (!is_right_critical && right_access->is_valid()) {
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
    } else {
        left_next();

        // If left iterator caught up the right one, move on to
        // the next section.
        if (left_access == right_access) {
            right_next();
        }
    }

    return right_access->is_valid();
}

void PS::CNDependencyFinder::trim_accesses()
{
    while (last_accesses.begin() != left_access) {
        last_accesses.pop_front();
    }
}

void PS::CNDependencyFinder::left_next()
{
    left_access++;
    trim_accesses();
    update_is_left_critical();
}

void PS::CNDependencyFinder::update_is_left_critical()
{
    is_left_critical = left_access->is_valid() &&
                       is_critical_access(*left_access);
}

void PS::CNDependencyFinder::right_next()
{
    right_access++;
    update_is_right_critical();
}

void PS::CNDependencyFinder::update_is_right_critical()
{
    is_right_critical = right_access->is_valid() &&
                        is_critical_access(*right_access);
}

bool PS::CNDependencyFinder::is_required_dependency()
{
    if (!left_access->is_valid() || !right_access->is_valid()) {
        return false;
    }

    if (!is_left_critical && !is_right_critical) {
        return false;
    }

    // Ignore all the races with inode_unlink operation, as this operation
    // is intended to mark different unrelated generations of inode entries.
    if (left_access->access_type == FileAccessType::inode_unlink ||
        right_access->access_type == FileAccessType::inode_unlink) {
        return false;
    }

    return !IDependencyFinder::find_common_make_and_dependency(left_access->context,
                                                               right_access->context);
}

void PS::DirLookupDependencyFinder::push_access(PS::AccessRecord access)
{
    if (access.access_type == FileAccessType::write) {
        if (access.return_code != 0 && access.return_code != -EEXIST) {
            return;
        }

        if (access.return_code == 0) {
            initial_access = access;
            write_targets.clear();
        }

        write_targets.insert(access.context);
    } else if (access.access_type == FileAccessType::dir_lookup) {
        if (access.return_code < 0) {
            return;
        }

        assert(!dir_lookup.is_valid());
        dir_lookup = access;
    }
}

bool PS::DirLookupDependencyFinder::next()
{
    dir_lookup = AccessRecord::invalid;
    return false;
}

bool PS::DirLookupDependencyFinder::is_required_dependency()
{
    if (!dir_lookup.is_valid() || !initial_access.is_valid()) {
        return false;
    }

    auto& dir_lookup_ctx = dir_lookup.context;

    for (const BuildContext& ctx : write_targets) {
        if (IDependencyFinder::find_common_make_and_dependency(ctx, dir_lookup_ctx)) {
            return false;
        }
    }

    return true;
}

const PS::AccessRecord& PS::DirLookupDependencyFinder::get_left_access()
{
    return initial_access;
}

const PS::AccessRecord& PS::DirLookupDependencyFinder::get_right_access()
{
    return dir_lookup;
}

bool PS::EntryBoundDependencyFinder::skip_access(const PS::AccessRecord& access)
{
    if (!access.is_successful()) {
        // This dependency finder is not interested in failed accesses
        return true;
    }

    return access.access_type == FileAccessType::unlink ||
           access.access_type == FileAccessType::dir_lookup;
}

bool PS::EntryBoundDependencyFinder::is_critical_access(const PS::AccessRecord& access)
{
    // All access types except FileAccessType::read are marked as critical.
    return access.access_type != FileAccessType::read;
}

bool PS::PathBoundDependencyFinder::skip_access(const PS::AccessRecord& access)
{
    if (!access.is_successful()) {
        // This dependency finder is not interested in failed accesses
        return true;
    }

    return access.access_type == FileAccessType::dir_lookup;
}

bool PS::PathBoundDependencyFinder::is_critical_access(const PS::AccessRecord& access)
{
    // To avoid duplicating reports from entry-bound dependency search, only races
    // involving unlink operation are checked here
    return access.access_type == FileAccessType::unlink;
}
