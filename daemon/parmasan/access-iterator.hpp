#pragma once

#include <cstddef>
#include <functional>
#include <iterator>
#include "access-record.hpp"

namespace PS
{

// This iterator is intended to be used in entry-bound race searching. It helps to
// iterate through operations that are interesting for the RaceSearchEngine.
//
// In particular, it helps to conveniently skip unlink operations, as they should not be visible to
// the entry-bound race search loop.

struct AccessIteratorFalsePredicate {
    bool operator()(const AccessRecord&)
    {
        return false;
    }
};

template <typename SkipAccessPredicate = AccessIteratorFalsePredicate>
struct AccessIterator {
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = AccessRecord;
    using pointer = const AccessRecord*;
    using reference = const AccessRecord&;

    explicit AccessIterator(const std::vector<AccessRecord>& container)
    {
        position = container.data();
        end = position + container.size();

        // If there are any invalid operations at the beginning
        // of the container, skip them.
        if (*this && SkipAccessPredicate()(*position))
            ++(*this);
    }

    const AccessRecord* position;
    const AccessRecord* end;

    reference operator*() const
    {
        return *position;
    }
    pointer operator->() const
    {
        return position;
    }

    AccessIterator& operator++()
    {
        while (*this) {
            position++;

            if (!*this || !SkipAccessPredicate()(*position)) {
                break;
            }
        }

        return *this;
    }

    AccessIterator operator++(int)
    {
        AccessIterator tmp = *this;
        ++(*this);
        return tmp;
    }

    AccessIterator operator+(int count)
    {
        assert(count >= 0);

        AccessIterator result = *this;
        while (count--) {
            ++result;
        }
        return result;
    }

    friend bool operator==(const AccessIterator& a, const AccessIterator& b)
    {
        return a.position == b.position;
    };

    friend bool operator!=(const AccessIterator& a, const AccessIterator& b)
    {
        return a.position != b.position;
    };

    explicit operator bool() const
    {
        return position < end;
    }
};

} // namespace PS
