
#include "race-search-engine.hpp"
#include "access-iterator.hpp"

namespace PS
{

bool RaceSearchEngine::find_common_make_and_dependency(Target* from, Target* to)
{
    // It's not required to call search_for_dependency on the entire target chain, since
    // if two targets are the same level and from the same makefile, they must have the same
    // parent target. So search_for_dependency is only called for the deepest pair of targets
    // sharing the same target database.

    // Balance depths.

    int to_depth = to->target_database->get_depth();
    while (from->target_database->get_depth() > to_depth) {
        from = from->target_database->get_parent_target();
    }

    int from_depth = from->target_database->get_depth();
    while (from_depth < to->target_database->get_depth()) {
        to = to->target_database->get_parent_target();
    }

    // Go up the target chain until target databases match.

    while (from && to && from->target_database != to->target_database) {
        from = from->target_database->get_parent_target();
        to = to->target_database->get_parent_target();
    }

    // Finally, check if these two targets depend on each other.

    if (from && to) {
        return search_for_dependency(from, to);
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

void RaceSearchEngine::report_race(const File* file, const AccessRecord& access_a,
                                   const AccessRecord& access_b) const
{
    m_out_stream << "race found at file '" << file->get_path() << "': ";
    m_out_stream << access_a.access_type << " at target '" << access_a.target->name << "', ";
    m_out_stream << access_b.access_type << " at target '" << access_b.target->name
                 << "' are unordered\n";
}

} // namespace PS
