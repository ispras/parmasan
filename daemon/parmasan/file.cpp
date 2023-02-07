
#include "file.hpp"

std::string PS::File::get_path() const {
    std::stringstream stream;
    walk_path(stream);
    return stream.str();
}

void PS::File::walk_path(std::stringstream& stream) const {
    if (m_parent) {
        m_parent->walk_path(stream);
        stream << '/' << m_name;
    } else {
        stream << m_name;
    }
}
PS::File* PS::File::get_child(const std::string& child_name) {
    auto it = m_children.find(child_name);
    if (it == m_children.end()) {

        std::unique_ptr<File> new_file = std::make_unique<File>(child_name);
        new_file->m_parent = this;
        File* new_file_ptr = new_file.get();
        m_children.emplace(child_name, std::move(new_file));

        return new_file_ptr;
    }

    return it->second.get();
}
