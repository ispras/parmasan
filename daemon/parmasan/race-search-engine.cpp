
#include "race-search-engine.hpp"
#include "access-iterator.hpp"

namespace PS
{

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

void RaceSearchEngine::reset()
{
    m_filename_database.reset();
    m_target_database.reset();
}

} // namespace PS
