
#include "target-database.hpp"
#include "race-search-engine.hpp"

bool PS::TargetDatabase::read_target_pid_event(BufferReader& reader) {
    pid_t pid = 0;
    if (!reader.read(&pid))
        return false;
    const char* target_name = reader.read_string();
    if (!target_name)
        return false;

    m_target_by_pid_instances[pid] = get_target_for_name(target_name);

    return true;
}
bool PS::TargetDatabase::read_dependency_event(BufferReader& reader) {
    const char* target_name = reader.read_string();
    const char* dependency_name = reader.read_string();

    if (!target_name || !dependency_name)
        return false;

    get_target_for_name(dependency_name)->dependents.push_back(get_target_for_name(target_name));

    return true;
}
PS::Target* PS::TargetDatabase::get_target_for_name(const std::string& name) {
    auto it = m_targets_by_names.find(name);
    if (it == m_targets_by_names.end()) {
        std::unique_ptr<Target> target = std::make_unique<Target>(name);
        Target* result = target.get();
        m_targets_by_names[name] = std::move(target);
        return result;
    }
    return it->second.get();
}
PS::Target* PS::TargetDatabase::get_target(pid_t pid) {
    auto it = m_target_by_pid_instances.find(pid);
    if (it == m_target_by_pid_instances.end())
        return nullptr;
    return it->second;
}
