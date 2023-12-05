
#include "access-record.hpp"

namespace PS
{

AccessRecord AccessRecord::invalid{FileAccessType::read, {}, nullptr};

}
