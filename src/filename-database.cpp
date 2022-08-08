
#include "filename-database.hpp"
#include "engine.hpp"

PS::File* PS::FilenameDatabase::get_file_for_entry(const PS::Entry& entry) {
    auto it = m_files.find(entry);
    if (it == m_files.end()) {
        return nullptr;
    }
    return it->second;
}

bool PS::FilenameDatabase::to_relative_path(std::string& path) {
    const std::string& build_directory = m_project_root->m_name;

    if (path.size() < build_directory.size())
        return false;

    if (path.compare(0, build_directory.size(), build_directory) != 0) {
        return false;
    }

    int i = 0;

    for (auto j = build_directory.size() + 1; j < path.size(); i++, j++) {
        path[i] = path[j];
    }

    path.resize(i);

    return true;
}
PS::File* PS::FilenameDatabase::get_file_for_relative_path(const std::string& path) {
    int index = 0;
    std::string folder_name;
    File* file = get_project_root();
    get_folder_name(path, index, folder_name);

    while (!folder_name.empty()) {
        auto it = file->m_children.find(folder_name);
        if(it == file->m_children.end()) return nullptr;
        file = it->second.get();
        folder_name.clear();
        get_folder_name(path, index, folder_name);
    }

    return file;
}
