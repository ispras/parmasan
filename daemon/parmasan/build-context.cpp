
#include "build-context.hpp"
#include "target-database.hpp"
#include "target.hpp"

PS::BuildContext PS::BuildContext::parent() const
{
    if (target) {
        return target->make_process->get_parent_context();
    }

    return {};
}

int PS::BuildContext::get_depth() const
{
    if (!*this) {
        return 0;
    }
    return target->make_process->get_depth();
}

void PS::BuildContext::up_to_depth(int target_depth)
{
    while (get_depth() > target_depth) {
        *this = parent();
    }
}
