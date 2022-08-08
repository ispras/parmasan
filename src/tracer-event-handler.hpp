#pragma once

#include "entry.hpp"
#include "file.hpp"
#include <fstream>
#include <unordered_map>

namespace PS {

struct PIDData {
    pid_t ppid;
    int instance;
};

class Engine;
class TracerEventHandler {
  public:
    explicit TracerEventHandler(Engine* engine) : m_engine(engine) {}

    Target* get_target_for_pid(pid_t pid);

    void read(std::ifstream&& stream);

  private:
    Engine* m_engine;
    std::unordered_map<pid_t, PIDData> pid_database;
};

} // namespace PS