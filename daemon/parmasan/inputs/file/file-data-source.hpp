// SPDX-License-Identifier: MIT

#pragma once

#include <fstream>
#include <unordered_set>
#include "../parmasan-data-source.hpp"

namespace PS
{

class ParmasanFileDataSource : public ParmasanDataSource
{
  public:
    ParmasanFileDataSource(const std::string& file_path)
        : m_input(file_path) {}
    virtual ~ParmasanFileDataSource() = default;

    bool loop() override;
    void disconnect_process(pid_t pid) override;
    void close() override;

  private:
    void skip_word();
    void skip_whitespaces();

    std::ifstream m_input;
    std::unordered_set<pid_t> connected_pids;
};

} // namespace PS
