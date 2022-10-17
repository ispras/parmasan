#pragma once

#include <cstdlib>
#include <functional>
#include <sys/stat.h>

namespace PS {

struct Entry {
    dev_t device; /* ID of device containing file */
    ino_t inode;  /* File serial number */

    bool operator==(const Entry& other) const {
        return (device == other.device && inode == other.inode);
    }
};

} // namespace PS

namespace std {

template <> struct hash<PS::Entry> {
    std::size_t operator()(const PS::Entry& key) const {
        return ((std::hash<dev_t>()(key.device) ^ hash<ino_t>()(key.inode)));
    }
};

} // namespace std