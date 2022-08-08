#pragma once

#include <cstring>
#include <string>
#include <cassert>
#include <ios>
#include "file-access-type.hpp"

namespace PS {
enum class TracerEventType { read, write, read_write, unlink, child };

bool is_file_operation(TracerEventType event);
FileAccessType get_file_operation(TracerEventType event);

} // namespace PS

template <class Stream> Stream& operator>>(Stream& stream, PS::TracerEventType& type) {

    char code[3] = {};

    while(!isalpha(code[0]) && !stream.fail()) {
        code[0] = stream.get();
    }
    code[1] = stream.get();

    if (strcmp(code, "RD") == 0)
        type = PS::TracerEventType::read;
    else if (strcmp(code, "RW") == 0)
        type = PS::TracerEventType::read_write;
    else if (strcmp(code, "WR") == 0)
        type = PS::TracerEventType::write;
    else if (strcmp(code, "UN") == 0)
        type = PS::TracerEventType::unlink;
    else if (strcmp(code, "CH") == 0)
        type = PS::TracerEventType::child;
    else
        stream.setstate(std::ios::failbit);

    return stream;
}