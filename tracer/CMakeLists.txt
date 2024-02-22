project(tracer)

add_executable(tracer
        main.cpp
        tracer/tracee.c
        tracer/seccomp.c
        tracer/tracer.c
        shared/structures.c
        tracer/path.c
        tracer/pidset.c)

target_include_directories(tracer PUBLIC .)
