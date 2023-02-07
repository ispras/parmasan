cmake_minimum_required(VERSION 3.10)
project(tracer)

set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g3 -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address")

set(CMAKE_C_STANDARD 11)

add_executable(tracer
        main.cpp
        tracer/tracee.c
        tracer/seccomp.c
        tracer/tracer.c
        shared/structures.h
        shared/structures.c
        tracer/tracee.h
        tracer/seccomp.h
        tracer/tracer.h
        tracer/openat2.h
        tracer/renameat2.h)

target_include_directories(tracer PUBLIC .)