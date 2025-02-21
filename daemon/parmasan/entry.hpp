// SPDX-License-Identifier: MIT

#pragma once

#include <cstdlib>
#include <functional>
#include <sys/stat.h>

namespace PS
{

struct Entry {
    dev_t device;
    ino_t inode;

    bool operator==(const Entry& other) const
    {
        return (device == other.device && inode == other.inode);
    }
};

} // namespace PS

namespace std
{

template <>
struct hash<PS::Entry> {
    std::size_t operator()(const PS::Entry& key) const
    {
        return ((std::hash<dev_t>()(key.device) ^ hash<ino_t>()(key.inode)));
    }
};

template <class Stream>
Stream& operator<<(Stream& stream, PS::Entry& entry)
{
    stream << entry.device << ':' << entry.inode;
    return stream;
}

} // namespace std
