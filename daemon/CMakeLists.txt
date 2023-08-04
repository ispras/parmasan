
add_executable(parmasan
        daemon-connection-data.cpp
        daemon-connection-data.hpp
        daemon/daemon-base.hpp
        daemon/daemon-base.cpp
        main.cpp
        make-connection-data.cpp
        make-connection-data.hpp
        parmasan-daemon.cpp
        parmasan-daemon.hpp
        parmasan/access-iterator.hpp
        parmasan/access-record.hpp
        parmasan/entry-history.cpp
        parmasan/entry-history.hpp
        parmasan/entry.hpp
        parmasan/file-access-type.hpp
        parmasan/file.cpp
        parmasan/file.hpp
        parmasan/filename-database.cpp
        parmasan/filename-database.hpp
        parmasan/race-search-engine.cpp
        parmasan/race-search-engine.hpp
        parmasan/required-dependency-finder.hpp
        parmasan/target-database.cpp
        parmasan/target-database.hpp
        parmasan/target.cpp
        parmasan/target.hpp
        parmasan/tracer-event-handler.cpp
        parmasan/tracer-event-handler.hpp
        shared/structures.cpp
        shared/structures.hpp
        tracer-connection-data.cpp
        tracer-connection-data.hpp
        utils/path-walker.cpp
        utils/path-walker.hpp
        utils/run-shell.cpp
        utils/run-shell.hpp parmasan/entry-bound-dependency-search.hpp parmasan/path-bound-dependency-search.hpp parmasan/access-record.cpp)

target_include_directories(parmasan PUBLIC .)
