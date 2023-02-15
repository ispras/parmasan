cmake_minimum_required(VERSION 3.10)
project(parmasan)

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(tracer)
add_subdirectory(daemon)

install(TARGETS tracer parmasan)
