
#include "breakpoint-config.hpp"

bool PS::BreakpointFlags::add_char(char c)
{
    switch (c) {
    case 'r':
        read_bit = true;
        return true;
    case 'w':
        write_bit = true;
        return true;
    case 'a':
        access_bit = true;
        return true;
    case 'u':
        unlink_bit = true;
        return true;
    case 'R':
        race_bit = true;
        return true;
    default:
        return false;
    }
}

bool PS::BreakpointConfig::parse(const char* description)
{
    auto colon = strchr(description, ':');
    const char* glob = colon + 1;

    if (!colon || *glob == '\0') {
        return false;
    }

    while (description != colon) {
        if (!flags.add_char(*description)) {
            return false;
        }
        description++;
    }

    if (*glob == '/') {
        path = glob;
    } else {
        path = (std::filesystem::current_path() /= glob).lexically_normal().string();
    }

    return true;
}
