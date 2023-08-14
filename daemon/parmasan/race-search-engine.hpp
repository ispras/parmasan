#pragma once

#include <fstream>
#include <memory>
#include <ostream>
#include <unordered_map>
#include "access-record.hpp"
#include "file.hpp"
#include "filename-database.hpp"
#include "target-database.hpp"
#include "tracer-event-handler.hpp"

namespace PS
{

class RaceSearchEngine
{
  public:
    TargetDatabase m_target_database{};
    FilenameDatabase m_filename_database{};

    RaceSearchEngine(RaceSearchEngine&& move) = delete;
    RaceSearchEngine(const RaceSearchEngine& copy) = delete;
    RaceSearchEngine& operator=(RaceSearchEngine&& move_assign) = delete;
    RaceSearchEngine& operator=(const RaceSearchEngine& copy_assign) = delete;

    explicit RaceSearchEngine(std::ostream& out_stream)
        : m_out_stream(out_stream) {}

    void reset();

    template <typename RequiredDependencyGenerator>
    void check_required_dependencies(File* file,
                                     RequiredDependencyGenerator& dependencies_to_check)
    {
        do {
            if (!dependencies_to_check.is_required_dependency()) {
                continue;
            }

            // Ignore all the races with inode_unlink operation, as this operation
            // is intended to mark different unrelated generations of inode entries.
            if (dependencies_to_check.left_access->access_type == FileAccessType::inode_unlink ||
                dependencies_to_check.right_access->access_type == FileAccessType::inode_unlink) {
                continue;
            }

            m_traverse_num++;
            if (!search_for_dependency(dependencies_to_check.left_access->target,
                                       dependencies_to_check.right_access->target)) {
                report_race(file, *dependencies_to_check.left_access,
                            *dependencies_to_check.right_access);
            }
        } while (dependencies_to_check.next());
    }

  private:
    bool search_for_dependency(Target* from, Target* to);
    void report_race(const File* file, const AccessRecord& access_a,
                     const AccessRecord& access_b) const;

    std::ostream& m_out_stream;
    unsigned long long m_traverse_num = 0;
};

} // namespace PS
