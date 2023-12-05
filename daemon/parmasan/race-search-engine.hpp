#pragma once

#include <fstream>
#include <memory>
#include <ostream>
#include <unordered_map>
#include "access-record.hpp"
#include "file.hpp"
#include "filename-database.hpp"
#include "race-search-engine-delegate.hpp"

namespace PS
{

class RaceSearchEngine
{
  public:
    FilenameDatabase m_filename_database{};

    RaceSearchEngine(RaceSearchEngine&& move) = delete;
    RaceSearchEngine(const RaceSearchEngine& copy) = delete;
    RaceSearchEngine& operator=(RaceSearchEngine&& move_assign) = delete;
    RaceSearchEngine& operator=(const RaceSearchEngine& copy_assign) = delete;

    explicit RaceSearchEngine() = default;

    template <typename RequiredDependencyGenerator>
    void check_required_dependencies(File* file,
                                     RequiredDependencyGenerator& dependencies_to_check)
    {
        do {
            // The delegate check is not moved outside the loop on purpose.
            // In case no delegate is set, the dependencies_to_check generator
            // should still be flushed.
            if (!m_delegate) {
                continue;
            }

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
            if (!find_common_make_and_dependency(*dependencies_to_check.left_access,
                                                 *dependencies_to_check.right_access)) {
                Race race{
                    .file = file,
                    .left_access = *dependencies_to_check.left_access,
                    .right_access = *dependencies_to_check.right_access,
                };
                m_delegate->handle_race(race);
            }
        } while (dependencies_to_check.next());
    }

    void set_delegate(RaceSearchEngineDelegate* delegate);

  private:
    bool find_common_make_and_dependency(const AccessRecord& access_a,
                                         const AccessRecord& access_b);
    bool search_for_dependency(Target* from, Target* to);

    RaceSearchEngineDelegate* m_delegate = nullptr;
    unsigned long long m_traverse_num = 0;
};

} // namespace PS
