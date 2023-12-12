#pragma once

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include "dependency-finder.hpp"

namespace PS
{

class File
{
  public:
    std::string m_name;
    std::unordered_map<std::string, std::unique_ptr<File>> m_children{};
    File* m_parent = nullptr;

    PathBoundDependencyFinder m_path_bound_dependency_finder;
    DirLookupDependencyFinder m_dir_lookup_dependency_finder;

    File(File&& move) = delete;
    File(const File& copy) = delete;
    File& operator=(File&& move_assign) = delete;
    File& operator=(const File& copy_assign) = delete;

    template <typename T>
    explicit File(T&& name)
        : m_name(std::forward<T>(name))
    {
        if (!m_name.empty() && m_name.back() == '/') {
            m_name.pop_back();
        }
    }
    explicit File(const char* name)
        : File(std::string(name)) {}

    File* get_child(const std::string& child_name);

    std::string get_path() const;

    void walk_path(std::stringstream& stream) const;
};
} // namespace PS
