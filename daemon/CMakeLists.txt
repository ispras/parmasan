
add_executable(parmasan
        parmasan/inputs/socket/socket-server.cpp
        main.cpp
        ../parmasan/make-connection-handler.cpp
        ../parmasan/parmasan-daemon.cpp
        parmasan/entry-history.cpp
        parmasan/file.cpp
        parmasan/filename-database.cpp
        parmasan/make-process.cpp
        parmasan/target.cpp
        shared/structures.cpp
        ../parmasan/tracer-process.cpp
        utils/path-walker.cpp
        utils/run-shell.cpp
        parmasan/access-record.cpp
        parmasan/build-context.cpp
        parmasan/process.cpp
        parmasan/dependency-finder.cpp
        interface/parmasan-interface.cpp
        interface/globs.cpp
        interface/helpers.cpp
        parmasan/inputs/socket/socket-data-source.cpp
        parmasan/inputs/file/file-data-source.cpp
        parmasan/dumper.cpp
        options.cpp
        utils/breakpoint-config.cpp)

target_include_directories(parmasan PUBLIC .)
