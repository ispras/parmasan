
#include "target-database.hpp"
#include "../../parmasan/make-process.hpp"
#include "target-database.hpp"

bool PS::MakeProcess::read_target_pid_event(const char* buffer)
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

    ProcessData* process = m_attached_tracer->get_alive_process(pid);

    m_target_by_process[process] = get_target_for_name(name);

    return true;
}
bool PS::MakeProcess::read_dependency_event(const char* buffer)
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
bool PS::MakeProcess::read_goal_event(const char* buffer)
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

PS::Target* PS::MakeProcess::get_target_for_process(PS::ProcessData* process) const
{
    while (process) {
        auto it = m_target_by_process.find(process);
        if (it != m_target_by_process.end())
            return it->second;
        process = process->parent;
    }
    return nullptr;
}

PS::Target* PS::MakeProcess::get_target_for_name(const std::string& name)
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

void PS::MakeProcess::set_parent_context(PS::BuildContext parent_context)
{
    m_parent_context = parent_context;
    m_depth = parent_context.get_depth() + 1;
}

PS::BuildContext PS::MakeProcess::get_parent_context() const
{
    return m_parent_context;
}

int PS::MakeProcess::get_depth() const
{
    return m_depth;
}
PS::MakeGoal* PS::MakeProcess::get_current_goal() const
{
    if (m_goals.empty()) {
        return nullptr;
    }
    return m_goals.back().get();
}

PS::ProcessData* PS::MakeProcess::get_process_data() const
{
    return m_process_data;
}

void PS::MakeProcess::set_process_data(PS::ProcessData* process_data)
{
    m_process_data = process_data;
}

const std::unordered_map<std::string, std::unique_ptr<PS::Target>>&
PS::MakeProcess::get_targets_by_names() const
{
    return m_targets_by_names;
}

bool PS::MakeProcess::search_for_dependency(Target* from, Target* to)
{
    m_traverse_num++;
    return search_for_dependency_rec(from, to);
}

bool PS::MakeProcess::search_for_dependency_rec(Target* from, Target* to)
{
    if (from->last_traverse_num == m_traverse_num)
        return false;

    if (from == to)
        return true;

    from->last_traverse_num = m_traverse_num;

    for (auto& dependent : from->dependents) {
        if (search_for_dependency_rec(dependent, to)) {
            return true;
        }
    }

    return false;
}
