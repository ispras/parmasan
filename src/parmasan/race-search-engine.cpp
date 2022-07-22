
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
    for (int i = 0; i < entry->accesses.size(); i++) {
        auto& read_access = entry->accesses[i];
        if (read_access.access_type != FileAccessType::read &&
            read_access.access_type != FileAccessType::read_write)
            continue;

        for (int j = 0; j < entry->accesses.size(); j++) {
            auto& write_access = entry->accesses[j];
            if (write_access.access_type != FileAccessType::write &&
                write_access.access_type != FileAccessType::read_write)
                continue;

            if (!search_for_depencency(read_access.target, write_access.target) &&
                !search_for_depencency(write_access.target, read_access.target)) {

                report_race(entry, read_access, write_access);
            }
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