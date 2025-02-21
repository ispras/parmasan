# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.10)
project(parmasan)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(tracer)
add_subdirectory(daemon)

install(TARGETS tracer parmasan)
