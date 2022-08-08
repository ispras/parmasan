
#include "engine.hpp"
#include "entry.hpp"
#include <filesystem>

int main() {
    std::string build_directory = (std::string)std::filesystem::current_path();

    PS::Engine engine(build_directory);

    engine.read_dependencies(std::ifstream("dep_graph.txt"));
    engine.read_target_pids(std::ifstream("pid.txt"));
    engine.read_accesses(std::ifstream("tracer-result.txt"));

    return 0;
}
