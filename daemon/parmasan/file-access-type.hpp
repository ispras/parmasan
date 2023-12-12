#pragma once

namespace PS
{
enum class FileAccessType {
    read,
    write,
    read_write,
    unlink,
    inode_unlink,
    dir_lookup
};
}

template <class Stream>
Stream& operator<<(Stream& stream, PS::FileAccessType type)
{

    switch (type) {

    case PS::FileAccessType::write:
        stream << "write";
        break;
    case PS::FileAccessType::read_write:
        stream << "read+write";
        break;
    case PS::FileAccessType::read:
        stream << "read";
        break;
    case PS::FileAccessType::unlink:
        stream << "unlink";
        break;
    case PS::FileAccessType::inode_unlink:
        stream << "complete inode unlink";
        break;
    case PS::FileAccessType::dir_lookup:
        stream << "directory access";
        break;
    }

    return stream;
}
