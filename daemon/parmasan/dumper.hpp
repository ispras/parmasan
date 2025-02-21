// SPDX-License-Identifier: MIT

#pragma once

#include <fstream>
#include "parmasan/inputs/parmasan-data-source.hpp"

namespace PS
{

class ParmasanDumper : public ParmasanInputDelegate
{
  public:
    ParmasanDumper(const std::string& output_path, std::ios::openmode mode)
        : m_output(output_path, mode) {}

  private:
    void process_connected(ParmasanDataSource* input, pid_t pid) override;
    void process_message(ParmasanDataSource* input, pid_t pid, std::string_view message) override;
    void process_disconnected(ParmasanDataSource* input, pid_t pid) override;

    std::ofstream m_output;
};

} // namespace PS
