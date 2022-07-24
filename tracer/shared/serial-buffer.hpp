#pragma once

#include <cstring>
#include <vector>

class SerialBuffer {
  public:
    explicit SerialBuffer() = default;
    SerialBuffer(SerialBuffer&& move) noexcept = default;
    SerialBuffer(const SerialBuffer& copy) = default;

    template <typename T> bool write(T* target) {
        m_buffer.insert(m_buffer.end(), (char*)target, (char*)(target + 1));
        return true;
    }

    void write_string(const std::string& string) {
        m_buffer.insert(m_buffer.end(), string.begin(), string.end());
        m_buffer.push_back('\0');
    }

    void clear() { m_buffer.clear(); }

    char* data() { return m_buffer.data(); }

    size_t size() { return m_buffer.size(); }

  private:
    std::vector<char> m_buffer{};
};