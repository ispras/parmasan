
#include "tracer/tracer.hpp"
#include <cstdio>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Please, specify which program to trace\n");
        return 0;
    }

    Tracer t("/tmp/parmasan-socket.sock");
    t.trace(argv + 1);

    return 0;
}
