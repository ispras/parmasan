#pragma once

#include "race.hpp"

namespace PS
{

class RaceSearchEngineDelegate
{
  public:
    virtual void handle_race(const Race& race) = 0;
    virtual void handle_access(const AccessRecord& access, const File& file) = 0;
};

} // namespace PS
