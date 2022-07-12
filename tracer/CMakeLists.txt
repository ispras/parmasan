cmake_minimum_required(VERSION 3.10)
project(tracer)

set(CMAKE_CXX_FLAGS "-g3 -fsanitize=address -DDEBUG -DDEBUG_FILE_PATHS")

set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE files "${CMAKE_SOURCE_DIR}/src/*.cpp" "${CMAKE_SOURCE_DIR}/src/*.hpp")
add_executable(tracer ${files})