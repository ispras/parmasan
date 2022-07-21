#include "tracer.hpp"
#include <cstdio>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Please, specify which program to trace\n");
        return 0;
    }

    tracer t("./tracer-result.txt", "./tracer-deleted-files.txt");
    t.trace(argv + 1);

    return 0;
}
