#pragma once

#include <cstdlib>
#include <functional>
#include <sys/stat.h>

namespace PS {

struct Entry {
    dev_t m_device;
    ino_t m_inode;

    bool operator==(const Entry& other) const {
        return (m_device == other.m_device && m_inode == other.m_inode);
    }
};

} // namespace PS

namespace std {

template <> struct hash<PS::Entry> {
    std::size_t operator()(const PS::Entry& key) const {
        return ((std::hash<dev_t>()(key.m_device) ^ hash<ino_t>()(key.m_inode)));
    }
};

template <class Stream> Stream& operator>>(Stream& stream, PS::Entry& entry) {
    stream >> entry.m_device;
    stream.get();
    stream >> entry.m_inode;
    return stream;
}

template <class Stream> Stream& operator<<(Stream& stream, PS::Entry& entry) {
    stream << entry.m_device << ':' << entry.m_inode;
    return stream;
}

} // namespace std