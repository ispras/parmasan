#pragma once

#include <cstring>
#include <vector>

class BufferReader {
  public:
    explicit BufferReader(const char* buffer, size_t length) : m_length(length), m_buffer(buffer) {}
    BufferReader(BufferReader&& move) noexcept = default;
    BufferReader(const BufferReader& copy) = delete;

    template <typename T> bool read(T* target) {
        if (m_length < m_index + sizeof(T))
            return false;
        memcpy(target, &m_buffer[m_index], sizeof(T));
        m_index += sizeof(T);
        return true;
    }

    const char* read_string() {
        const char* result = &m_buffer[m_index];
        while (m_index < m_length) {
            if (m_buffer[m_index++] == '\0')
                return result;
        }
        return nullptr;
    }

  private:
    size_t m_length;
    size_t m_index = 0;
    const char* m_buffer;
};