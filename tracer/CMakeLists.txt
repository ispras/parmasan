project(tracer)

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
        tracer/renameat2.h
        tracer/path.c
        tracer/path.h
        tracer/pidset.h
        tracer/pidset.c)

target_include_directories(tracer PUBLIC .)
