
#include "engine.hpp"

namespace PS {

void Engine::read_dependencies(std::ifstream&& stream) {
    std::string target_name;
    std::string dependency_name;

    //    std::cout << stream.is_open() << "\n";

    while (stream >> target_name >> dependency_name) {
        target_name.pop_back();

        m_target_database.get_target_for_name(dependency_name)
            ->m_dependents.push_back(m_target_database.get_target_for_name(target_name));
    }
}
void Engine::read_accesses(std::ifstream&& stream) {
    m_tracer_event_handler.read(std::move(stream));
    search_for_races(m_filename_database.get_project_root());
}
bool Engine::search_for_depencency(Target* from, Target* to) {
    if (from == to)
        return true;

    // TODO: bfs?

    for (auto& dependent : from->m_dependents) {
        if (search_for_depencency(dependent, to)) {
            return true;
        }
    }

    return false;
}
void Engine::search_for_races(File* file) {
    for (int i = 0; i < file->m_accesses.size(); i++) {
        auto& read_access = file->m_accesses[i];
        if (read_access.m_access_type != FileAccessType::read &&
            read_access.m_access_type != FileAccessType::read_write)
            continue;

        for (int j = 0; j < file->m_accesses.size(); j++) {
            auto& write_access = file->m_accesses[j];
            if (write_access.m_access_type != FileAccessType::write &&
                write_access.m_access_type != FileAccessType::read_write)
                continue;

            if (!search_for_depencency(read_access.m_target, write_access.m_target) &&
                !search_for_depencency(write_access.m_target, read_access.m_target)) {

                report_race(file, read_access, write_access);
            }
        }
    }

    for (auto& entry : file->m_children) {
        search_for_races(entry.second.get());
    }
}
void Engine::report_race(const File* file, const FileAccessRecord& access_a,
                         const FileAccessRecord& access_b) const {
    std::cout << "race found at file '" << file->get_relative_path() << "': ";
    std::cout << access_b.m_access_type << " at target '" << access_b.m_target->m_name
              << "', ";
    std::cout << access_a.m_access_type << " at target '" << access_a.m_target->m_name
              << "' are unordered\n";
}
void Engine::dump(File* file) {
    std::cout << "Dumping accesses to file '" << file->get_relative_path() << "':\n";

    for (auto& access : file->m_accesses) {
        std::cout << " - " << access.m_access_type << " from "
                  << access.m_target->m_name << "\n";
    }

    for (auto& entry : file->m_children) {
        dump(entry.second.get());
    }
}

} // namespace PS