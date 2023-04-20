
#include "race-search-engine.hpp"
#include "access-iterator.hpp"
#include "required-dependency-generator.hpp"

namespace PS
{

bool RaceSearchEngine::search_for_dependency(Target* from, Target* to)
{
    if (from == to)
        return true;

    // TODO: bfs?

    for (auto& dependent : from->dependents) {
        if (search_for_dependency(dependent, to)) {
            return true;
        }
    }

    return false;
}
void RaceSearchEngine::search_for_races()
{
    for (auto& it : m_filename_database.get_entries()) {
        search_for_races_on_entry(it.second.get());
    }

    search_for_races_on_path(m_filename_database.get_root());
}

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

void RaceSearchEngine::search_for_races_on_entry(EntryData* entry)
{

    // The dependency generator is configured to ignore all the unlink operations.
    // The reason behind it is that unlink events can lead to false positives
    // if the inode has multiple file paths.
    // Races with unlink operations are detected in path-bound race searching.

    struct UnlinkSkipPredicate {
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

    RequiredDependencyGenerator<CriticalAccessPredicate, UnlinkSkipPredicate> dependency_generator(
        entry->accesses);

    check_access_ordering(entry->last_known_file, dependency_generator);
}

void RaceSearchEngine::search_for_races_on_path(File* file)
{

    // To avoid duplicating reports, only races involving unlink operation should be checked here,
    // so mark unlink accesses are critical.

    struct CriticalAccessPredicate {
        bool operator()(const AccessRecord& access)
        {
            return access.access_type == FileAccessType::unlink;
        }
    };

    RequiredDependencyGenerator<CriticalAccessPredicate> dependency_generator(file->m_accesses);

    check_access_ordering(file, dependency_generator);

    for (auto& child : file->m_children) {
        search_for_races_on_path(child.second.get());
    }
}

void RaceSearchEngine::report_race(const File* file, const AccessRecord& access_a,
                                   const AccessRecord& access_b) const
{
    m_out_stream << "race found at file '" << file->get_path() << "': ";
    m_out_stream << access_a.access_type << " at target '" << access_a.target->name << "', ";
    m_out_stream << access_b.access_type << " at target '" << access_b.target->name
                 << "' are unordered\n";
}
void RaceSearchEngine::dump(EntryData* entry)
{
    m_out_stream << "Dumping m_accesses to entry '" << entry->last_known_file->get_path()
                 << "':\n";

    for (auto& access : entry->accesses) {
        m_out_stream << " - " << access.access_type << " from " << access.target->name << "\n";
    }
}

} // namespace PS
