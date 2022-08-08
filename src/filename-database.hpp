#pragma once

#include "entry.hpp"
#include "file.hpp"
#include "utils.hpp"
#include <fstream>
#include <unordered_map>

namespace PS {

class Engine;
class FilenameDatabase {
  public:
    template <typename T>
    explicit FilenameDatabase(Engine* engine, T&& project_root)
        : m_engine(engine), m_project_root(std::make_unique<File>(std::forward<T>(project_root)))
    {
    }

    File* get_file_for_entry(const Entry& entry);
    File* get_file_for_relative_path(const std::string& path);

    File* get_project_root() {
        return m_project_root.get();
    }

    File* get_file_child(File* file, const std::string& child_name, const Entry& entry) {
        auto it = file->m_children.find(child_name);
        if (it == file->m_children.end()) {

            std::unique_ptr<File> new_file = std::make_unique<File>(child_name);
            new_file->m_parent = file;
            m_files[entry] = file;
            File* result = new_file.get();
            file->m_children.emplace(child_name, std::move(new_file));
            return result;
        }

        return it->second.get();
    }

    File* update_file(std::string absolute_path, const Entry& entry) {
        if(!to_relative_path(absolute_path)) return nullptr;

        int index = 0;
        std::string folder_name;
        File* file = get_project_root();
        get_folder_name(absolute_path, index, folder_name);

        while (!folder_name.empty()) {
            file = get_file_child(file, folder_name, entry);
            folder_name.clear();
            get_folder_name(absolute_path, index, folder_name);
        }

        return file;
    }

  private:

    bool to_relative_path(std::string& path);

    std::unique_ptr<File> m_project_root{};
    std::unordered_map<Entry, File*> m_files;
    Engine* m_engine;
};

} // namespace PS