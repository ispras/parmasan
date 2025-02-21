// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>

class PathWalker
{
  public:
    explicit PathWalker(const std::string& path)
        : m_path(path) {}

    std::optional<std::string_view> next_component()
    {
        m_index = m_path.find_first_not_of('/', m_index);
        if (m_index == std::string::npos) {
            return std::nullopt;
        }

        auto component_begin = m_index;

        m_index = m_path.find_first_of('/', m_index);
        if (m_index == std::string::npos) {
            m_index = m_path.size();
        }

        return std::string_view(&m_path[component_begin], m_index - component_begin);
    }

  private:
    size_t m_index = 0;
    const std::string& m_path;
};
