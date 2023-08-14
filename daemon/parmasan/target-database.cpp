
#include "target-database.hpp"
#include "race-search-engine.hpp"

bool PS::TargetDatabase::read_target_pid_event(const char* buffer)
{

    size_t len = 0;
    int res = 0;

    if (sscanf(buffer, "%zu %n", &len, &res) != 1) {
        return false;
    }

    buffer += res;
    std::string name(buffer, len);

    buffer += len;
    pid_t pid = 0;

    if (sscanf(buffer, "%d %n", &pid, &res) != 1) {
        return false;
    }

    m_target_by_pid_instances[pid] = get_target_for_name(name);

    return true;
}
bool PS::TargetDatabase::read_dependency_event(const char* buffer)
{
    size_t str_length = 0;
    int res = 0;

    if (sscanf(buffer, "%zu %n", &str_length, &res) != 1) {
        return false;
    }
    buffer += res;
    std::string target_name(buffer, str_length);

    buffer += str_length;
    if (sscanf(buffer, "%zu %n", &str_length, &res) != 1) {
        return false;
    }
    buffer += res;
    while (*buffer == ' ')
        buffer++;
    std::string dependency_name(buffer, str_length);

    Target* target = get_target_for_name(target_name);
    Target* dependency = get_target_for_name(dependency_name);

    auto& dependents = dependency->dependents;

    if (dependents.find(target) == dependents.end()) {
        dependents.insert(target);
    }

    return true;
}
PS::Target* PS::TargetDatabase::get_target_for_name(const std::string& name)
{
    auto it = m_targets_by_names.find(name);
    if (it == m_targets_by_names.end()) {
        std::unique_ptr<Target> target = std::make_unique<Target>(name);
        Target* result = target.get();
        m_targets_by_names[name] = std::move(target);
        return result;
    }
    return it->second.get();
}
PS::Target* PS::TargetDatabase::get_target(pid_t pid)
{
    auto it = m_target_by_pid_instances.find(pid);
    if (it == m_target_by_pid_instances.end())
        return nullptr;
    return it->second;
}
void PS::TargetDatabase::reset()
{
    m_target_by_pid_instances.clear();
    m_targets_by_names.clear();
}
