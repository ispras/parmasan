#pragma once

#include "entry-history.hpp"
#include "entry.hpp"
#include "file.hpp"
#include <fstream>
#include <unordered_map>

namespace PS {

class RaceSearchEngine;
class FilenameDatabase {
  public:
    explicit FilenameDatabase() = default;

    File* get_root() { return m_root.get(); }

    EntryData* update_file(const std::string& pathname, const Entry& entry);

    std::unordered_map<Entry, std::unique_ptr<EntryData>>& get_entries() { return m_entries; };

  private:
    std::unique_ptr<File> m_root = std::make_unique<File>("/");
    std::unordered_map<Entry, std::unique_ptr<EntryData>> m_entries;
};

} // namespace PS