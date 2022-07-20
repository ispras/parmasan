#pragma once

#include <sys/stat.h>
#include <cstdlib>
#include <functional>

struct FileNode {
    dev_t m_device;
    ino_t m_inode;

    bool operator==(const FileNode& other) const {
        return (m_device == other.m_device && m_inode == other.m_inode);
    }
};

namespace std {

template <> struct hash<FileNode> {
    std::size_t operator()(const FileNode& key) const {
        return ((std::hash<dev_t>()(key.m_device) ^ hash<ino_t>()(key.m_inode)));
    }
};

}