#!/usr/bin/env python3

import sys
from collections import defaultdict

graph = defaultdict(set)

for line in open(sys.argv[1]):
    try:
        target, deps = line.split(":")
        graph[target].update(deps.split())
    except ValueError:
        pass


for target in graph:
    print(target, ":")
    print(graph[target])
