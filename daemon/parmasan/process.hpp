#pragma once

#include <functional>
#include <string>
#include <sys/types.h>

namespace PS
{

class MakeProcess;

struct PidEpoch {
    pid_t pid;
    unsigned int epoch;

    bool operator==(const PidEpoch& other) const
    {
        return pid == other.pid && epoch == other.epoch;
    }
};

struct ProcessData {
    PidEpoch id{};
    MakeProcess* make_process = nullptr;

    ProcessData* parent = nullptr;
    ProcessData* first_child = nullptr;
    ProcessData* next_sibling = nullptr;

    std::string cmd_line;

    const char* get_executable_name() const;
    const char* get_argv_0() const;
    const char* get_next_arg(const char* arg) const;

    bool dead = false;

    MakeProcess* get_make_process();
    ProcessData* get_make_process_data();
};

} // namespace PS

namespace std
{

template <>
struct hash<PS::PidEpoch> {
    std::size_t operator()(const PS::PidEpoch& key) const
    {
        return std::hash<unsigned long long>()(
            key.pid * 2147483647 // This is a prime number
            + key.epoch);
    }
};

} // namespace std
