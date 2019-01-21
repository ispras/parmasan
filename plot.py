#!/usr/bin/env python3

# Usage:
# 1. Run modified [re]make that outputs dependencies to log.* files
# 2. E.g.: plot.py <(cat log.*) | dot -Tpng > 1.png

import sys
import errno
from collections import defaultdict

graph = defaultdict(set)

for line in open(sys.argv[1]):
    try:
        target, deps = line.split(":")
        graph[target].update(deps.split())
    except ValueError:
        pass


try:
    # print("digraph G {")
    for v in graph:
        for dest in graph[v]:
            print('"{}" -> "{}"'.format(v, dest))
    # print("}")
except IOError as e:
    if e.errno == errno.EPIPE:
        pass
    else:
        raise
