#pragma once

#include "entry.hpp"
#include "file.hpp"
#include "filename-database.hpp"
#include "iostream"
#include "target-database.hpp"
#include "tracer-event-handler.hpp"
#include "utils.hpp"
#include <fstream>
#include <memory>
#include <unordered_map>

namespace PS {

struct Engine {
    TargetDatabase m_target_database;
    FilenameDatabase m_filename_database;
    TracerEventHandler m_tracer_event_handler;

    Engine(Engine&& move) = delete;
    Engine(const Engine& copy) = delete;
    Engine& operator=(Engine&& move_assign) = delete;
    Engine& operator=(const Engine& copy_assign) = delete;

    template <typename T>
    explicit Engine(T&& build_directory)
        : m_target_database(this), m_filename_database(this, std::forward<T>(build_directory)), m_tracer_event_handler(this) {

    }

    void read_dependencies(std::ifstream&& stream);

    void read_target_pids(std::ifstream&& stream) { m_target_database.read(std::move(stream)); }

    void read_accesses(std::ifstream&& stream);

    bool search_for_depencency(Target* from, Target* to);

    void search_for_races(File* file);;

    void dump(File* file);
    void report_race(const File* file, const FileAccessRecord& read_access,
                     const FileAccessRecord& write_access) const;
};

} // namespace PS