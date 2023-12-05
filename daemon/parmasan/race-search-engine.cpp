
#include "race-search-engine.hpp"
#include "access-iterator.hpp"
#include "parmasan/target.hpp"

namespace PS
{

bool RaceSearchEngine::find_common_make_and_dependency(const AccessRecord& access_a,
                                                       const AccessRecord& access_b)
{
    BuildContext a_ctx = access_a.context;
    BuildContext b_ctx = access_b.context;

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
        return search_for_dependency(a_ctx.target, b_ctx.target);
    }

    // This might occur if the root makefile re-executed itself.
    // In this case, parmasan considers that the new re-executed process
    // is a sibling of the old make process with the same parent target.
    // But if the make process. didn't have any parent target, its sibling
    // won't have it as well. In this case, targets are considered
    // to be dependent.
    return true;
}

bool RaceSearchEngine::search_for_dependency(Target* from, Target* to)
{
    if (from->last_traverse_num == m_traverse_num)
        return false;

    if (from == to)
        return true;

    from->last_traverse_num = m_traverse_num;

    for (auto& dependent : from->dependents) {
        if (search_for_dependency(dependent, to)) {
            return true;
        }
    }

    return false;
}

void RaceSearchEngine::set_delegate(RaceSearchEngineDelegate* delegate)
{
    m_delegate = delegate;
}

} // namespace PS
