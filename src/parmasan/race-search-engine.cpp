
#include "race-search-engine.hpp"

namespace PS {

bool RaceSearchEngine::search_for_depencency(Target* from, Target* to) {
    if (from == to)
        return true;

    // TODO: bfs?

    for (auto& dependent : from->dependents) {
        if (search_for_depencency(dependent, to)) {
            return true;
        }
    }

    return false;
}
void RaceSearchEngine::search_for_races() {
    for (auto& it : m_filename_database.get_entries()) {
        search_for_races(it.second.get());
    }
}

void RaceSearchEngine::search_for_races(EntryData* entry) {
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

    for (int i = 1; i < entry->accesses.size(); i++) {
        auto& access_a = entry->accesses[i - 1];
        auto& access_b = entry->accesses[i];
        if (access_a.access_type == FileAccessType::inode_release)
            continue;

        if (access_a.access_type == FileAccessType::read &&
            access_b.access_type == FileAccessType::read) {
            continue;
        }

        if (!search_for_depencency(access_a.target, access_b.target)) {
            report_race(entry, access_a, access_b);
        }
    }
}
void RaceSearchEngine::report_race(const EntryData* file, const EntryAccessRecord& access_a,
                                   const EntryAccessRecord& access_b) const {
    std::cout << "race found at file '" << file->last_known_file->get_path() << "': ";
    std::cout << access_a.access_type << " at target '" << access_a.target->name << "', ";
    std::cout << access_b.access_type << " at target '" << access_b.target->name
              << "' are unordered\n";
}
void RaceSearchEngine::dump(EntryData* entry) {
    std::cout << "Dumping m_accesses to entry '" << entry->last_known_file->get_path() << "':\n";

    for (auto& access : entry->accesses) {
        std::cout << " - " << access.access_type << " from " << access.target->name << "\n";
    }
}

} // namespace PS