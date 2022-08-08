
#include "target-database.hpp"
#include "engine.hpp"

void PS::TargetDatabase::read(std::ifstream&& stream) {
    std::string target_name;
    pid_t pid = 0;

    while (stream >> pid) {
        stream.get();
        stream >> target_name;
        m_target_by_pid_instances[pid].push_back(get_target_for_name(target_name));
    }
}
