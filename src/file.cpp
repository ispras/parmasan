
#include "file.hpp"

PS::Entry PS::File::get_current_entry() const {
    std::string absolute_path = get_absolute_path();
    struct stat file_stat {};

    if (stat(absolute_path.c_str(), &file_stat) >= 0) {
        return {file_stat.st_dev, file_stat.st_ino};
    } else {
        return {0, 0};
    }
}
std::string PS::File::get_absolute_path() const {
    std::stringstream stream;
    walk_path(stream, true);
    return stream.str();
}
std::string PS::File::get_relative_path() const {
    std::stringstream stream;
    walk_path(stream, false);
    return stream.str();
}
void PS::File::walk_path(std::stringstream& stream, bool absolute) const {
    if (m_parent) {
        m_parent->walk_path(stream, absolute);
        if(absolute || m_parent->m_parent) {
            stream << '/';
        }
        stream << m_name;
    } else if (absolute) {
        stream << m_name;
    }
}
