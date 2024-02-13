#pragma once

#include <cstring>
#include <filesystem>
#include <string_view>

namespace PS
{

enum class BreakpointType {
    BREAK,
    WATCH
};

struct BreakpointFlags {
    unsigned char read_bit : 1;
    unsigned char write_bit : 1;
    unsigned char access_bit : 1;
    unsigned char race_bit : 1;
    unsigned char unlink_bit : 1;
    unsigned char inverted_bit : 1;
    unsigned char and_bit : 1;

    BreakpointFlags()
        : read_bit(false),
          write_bit(false),
          access_bit(false),
          race_bit(false),
          unlink_bit(false),
          inverted_bit(false),
          and_bit(false) {}

    BreakpointFlags(const char* init)
        : BreakpointFlags()
    {
        while (char c = *init++)
            add_char(c);
    }

    BreakpointFlags& exclude()
    {
        inverted_bit = true;
        and_bit = true;
        return *this;
    }

    BreakpointFlags& invert()
    {
        inverted_bit = true;
        and_bit = false;
        return *this;
    }

    bool add_char(char c);
};

struct BreakpointConfig {
    BreakpointType type;
    BreakpointFlags flags;
    std::string path;

    bool parse(const char* description);
};

} // namespace PS
