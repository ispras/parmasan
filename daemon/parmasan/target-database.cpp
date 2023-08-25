
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
bool PS::TargetDatabase::read_goal_event(const char* buffer)
{
    size_t str_length = 0;
    int res = 0;

    if (sscanf(buffer, "%zu %n", &str_length, &res) != 1) {
        return false;
    }
    buffer += res;
    std::string_view goal_name(buffer, str_length);

    // Make sure not to store the same goal multiple times. When
    // the build is parallel, make process might send a sequence of
    // identical GOAL messages. However, once the new goal is
    // received, the previous one won't be repeated anymore, since
    // the goal chain is only iterated forward.
    if (!m_goals.empty() && m_goals.back()->name == goal_name) {
        return true;
    }

    m_goals.push_back(std::make_unique<MakeGoal>(goal_name, this));

    return true;
}
PS::Target* PS::TargetDatabase::get_target_for_name(const std::string& name)
{
    auto it = m_targets_by_names.find(name);
    if (it == m_targets_by_names.end()) {
        std::unique_ptr<Target> target = std::make_unique<Target>(name, this);
        Target* result = target.get();
        m_targets_by_names[name] = std::move(target);
        return result;
    }
    return it->second.get();
}
PS::Target* PS::TargetDatabase::get_target(pid_t pid) const
{
    auto it = m_target_by_pid_instances.find(pid);
    if (it == m_target_by_pid_instances.end())
        return nullptr;
    return it->second;
}

void PS::TargetDatabase::set_parent_context(PS::BuildContext parent_context)
{
    m_parent_context = parent_context;
    m_depth = parent_context.get_depth() + 1;
}

PS::BuildContext PS::TargetDatabase::get_parent_context() const
{
    return m_parent_context;
}

int PS::TargetDatabase::get_depth() const
{
    return m_depth;
}
PS::MakeGoal* PS::TargetDatabase::get_current_goal() const
{
    if (m_goals.empty()) {
        return nullptr;
    }
    return m_goals.back().get();
}
