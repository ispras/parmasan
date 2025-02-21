// SPDX-License-Identifier: MIT

#include "process.hpp"
#include <cstring>

PS::ProcessData* PS::ProcessData::get_make_process_data()
{
    ProcessData* process = this;
    while (process) {
        if (process->make_process) {
            return process;
        }
        process = process->parent;
    }
    return nullptr;
}
PS::MakeProcess* PS::ProcessData::get_make_process()
{
    PS::ProcessData* make_process_data = get_make_process_data();
    if (make_process_data == nullptr) {
        return nullptr;
    }
    return make_process_data->make_process;
}

const char* PS::ProcessData::get_executable_name() const
{
    const char* slash = strrchr(get_argv_0(), '/');
    if (slash == NULL) {
        return get_argv_0();
    }
    return slash + 1;
}

const char* PS::ProcessData::get_argv_0() const
{
    return cmd_line.data();
}

const char* PS::ProcessData::get_next_arg(const char* arg) const
{
    if (arg == nullptr) {
        return nullptr;
    }

    const char* end = cmd_line.data() + cmd_line.size();

    arg = strchr(arg, '\0') + 1;

    if (arg >= end) {
        return nullptr;
    }

    return arg;
}
