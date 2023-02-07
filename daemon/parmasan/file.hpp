#pragma once

#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include "access-record.hpp"
#include "entry-history.hpp"
#include "entry.hpp"
#include "file-access-type.hpp"
#include "target.hpp"

namespace PS {

class File;

class File {
  public:
    std::string m_name;
    std::unordered_map<std::string, std::unique_ptr<File>> m_children{};
    Entry m_entry{};
    File* m_parent = nullptr;
    std::vector<AccessRecord> m_accesses{};

    File(File&& move) = delete;
    File(const File& copy) = delete;
    File& operator=(File&& move_assign) = delete;
    File& operator=(const File& copy_assign) = delete;

    template <typename T> explicit File(T&& name) : m_name(std::forward<T>(name)) {
        if (!m_name.empty() && m_name.back() == '/') {
            m_name.pop_back();
        }
    }
    explicit File(const char* name) : File(std::string(name)) {}

    File* get_child(const std::string& child_name);

    std::string get_path() const;

    void walk_path(std::stringstream& stream) const;
};
} // namespace PS