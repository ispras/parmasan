
#include <cstdio>
#include "tracer/tracer.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Please, specify which program to trace\n");
        return 0;
    }

    tracer_trace(argv + 1);

    return 0;
}
