#pragma once

#include "entry.hpp"
#include "file-access-type.hpp"
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include "target.hpp"

namespace PS {

struct File;
struct FileAccessRecord {
    FileAccessType m_access_type{};
    Target* m_target{};
};

struct File {
    std::string m_name;
    std::vector<FileAccessRecord> m_accesses{};
    std::unordered_map<std::string, std::unique_ptr<File>> m_children{};
    File* m_parent = nullptr;

    File(File&& move) = delete;
    File(const File& copy) = delete;
    File& operator=(File&& move_assign) = delete;
    File& operator=(const File& copy_assign) = delete;

    template <typename T> explicit File(T&& name) : m_name(std::forward<T>(name)) {
        if (!m_name.empty() && m_name.back() == '/') {
            m_name.pop_back();
        }
    }

    Entry get_current_entry() const;

    std::string get_absolute_path() const;
    std::string get_relative_path() const;

    void walk_path(std::stringstream& stream, bool absolute) const;
};
} // namespace PS