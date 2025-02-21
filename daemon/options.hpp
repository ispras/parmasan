// SPDX-License-Identifier: MIT

#pragma once

#include <fstream>
#include <iostream>
#include <getopt.h>
#include "parmasan/parmasan-daemon.hpp"
#include "utils/breakpoint-config.hpp"

namespace PS
{

extern const struct option long_options[];
extern const char* options_string;

class Options
{
  public:
    Options(int argc, char** argv)
        : m_argc(argc), m_argv(argv) {}

    bool parse();

    const char* o_output_fname = "parmasan-dump.txt";
    const char* o_input_fname = nullptr;
    std::ios_base::openmode o_output_mode = std::ofstream::out;
    std::string o_socket_name = "$parmasan-socket";
    PS::ParmasanInteractiveMode o_interactive_mode = PS::ParmasanInteractiveMode::NONE;
    bool o_dump = false;
    std::vector<BreakpointConfig> o_breakpoints;

  private:
    bool validate() const;
    bool store_breakpoint(int opt, const char* optarg);
    void print_usage();

    int m_argc;
    char** m_argv;
};

} // namespace PS
