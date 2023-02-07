#pragma once

#include <fstream>
#include <memory>
#include <unordered_map>
#include <ostream>
#include "access-record.hpp"
#include "entry.hpp"
#include "file.hpp"
#include "filename-database.hpp"
#include "iostream"
#include "target-database.hpp"
#include "tracer-event-handler.hpp"

namespace PS {

class RaceSearchEngine {
  public:
    TargetDatabase m_target_database{};
    FilenameDatabase m_filename_database{};

    RaceSearchEngine(RaceSearchEngine&& move) = delete;
    RaceSearchEngine(const RaceSearchEngine& copy) = delete;
    RaceSearchEngine& operator=(RaceSearchEngine&& move_assign) = delete;
    RaceSearchEngine& operator=(const RaceSearchEngine& copy_assign) = delete;

    explicit RaceSearchEngine(std::ostream& out_stream) : m_out_stream(out_stream) {}

    bool search_for_dependency(Target* from, Target* to);
    void search_for_races();
    void search_for_races_on_path(File* file);
    void search_for_races_on_entry(EntryData* entry);

    void dump(EntryData* file);
    void report_race(const File* file, const AccessRecord& access_a,
                     const AccessRecord& access_b) const;

  private:
    std::ostream& m_out_stream;

    template <typename RequiredDependencyGenerator>
    void check_access_ordering(File* file, RequiredDependencyGenerator& dependencies_to_check) {
        while (dependencies_to_check.next()) {

            // Ignore all the races with inode_unlink operation, as this operation
            // is intended to mark different unrelated generations of inode entries.
            if (dependencies_to_check.left_access->access_type == FileAccessType::inode_unlink ||
                dependencies_to_check.right_access->access_type == FileAccessType::inode_unlink) {
                continue;
            }

            if (!search_for_dependency(dependencies_to_check.left_access->target,
                                       dependencies_to_check.right_access->target)) {
                report_race(file, *dependencies_to_check.left_access,
                            *dependencies_to_check.right_access);
            }
        }
    }
};

} // namespace PS