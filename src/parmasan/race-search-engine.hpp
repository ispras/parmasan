#pragma once

#include "entry.hpp"
#include "file.hpp"
#include "filename-database.hpp"
#include "iostream"
#include "target-database.hpp"
#include "tracer-event-handler.hpp"
#include <fstream>
#include <memory>
#include <unordered_map>

namespace PS {

class RaceSearchEngine {
  public:
    TargetDatabase m_target_database{};
    FilenameDatabase m_filename_database{};

    RaceSearchEngine(RaceSearchEngine&& move) = delete;
    RaceSearchEngine(const RaceSearchEngine& copy) = delete;
    RaceSearchEngine& operator=(RaceSearchEngine&& move_assign) = delete;
    RaceSearchEngine& operator=(const RaceSearchEngine& copy_assign) = delete;

    explicit RaceSearchEngine() = default;

    bool search_for_depencency(Target* from, Target* to);
    void search_for_races();
    void search_for_races(EntryData* file);

    void dump(EntryData* file);
    void report_race(const EntryData* file, const EntryAccessRecord& read_access,
                     const EntryAccessRecord& write_access) const;
};

} // namespace PS