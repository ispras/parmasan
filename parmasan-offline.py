#!/usr/bin/env python3

# Usage:

# 1. Run modified [re]make that outputs dependencies (to log.* files) and
#    pid->target mappings (to pid.* files) under our fuse file system that
#    records accesses (fuse.log) and pid ancestry data (pidanc.log).
# 2. E.g.: ../parmasan-offline.py <(cat log.*) <(cat pid.*) pidanc.log fuse.log

import sys
import errno
import os
import itertools
from collections import defaultdict

def transitive_closure(graph):
    # First, build the original adjacency matrix.
    nodes = tuple(graph.keys())
    adj = defaultdict(dict)
    for v in nodes:
        for t in nodes:
            if v == t:
                adj[v][t] = True
            else:
                adj[v][t] = t in graph[v]
    # Now, compute the closure.
    # FIXME: n^3 is insane, since we have a tree.
    for k in nodes:
        for i in nodes:
            for j in nodes:
                adj[i][j] |= adj[i][k] and adj[k][j]
    return adj

def get_target(pid):
    global target_by_pid
    global parent
    while pid not in target_by_pid:
        pid = parent[pid]
    return target_by_pid[pid]


# The dependency graph.  Nodes are make targets.
graph = defaultdict(set)
for line in open(sys.argv[1]):
    try:
        target, deps = line.split(":")
        graph[target].update(deps.split())
    except ValueError:
        pass

# The pid->target mapping (which target is the process building).
target_by_pid = {}
for line in open(sys.argv[2]):
    pid, target = line[:-1].split(": ")
    target_by_pid[pid] = target

parent = {}
for line in open(sys.argv[3]):
    prev = 0
    for pid in line.split():
        if prev != 0:
            if prev in parent and parent[prev] != pid:
                print("inconsistent pid ancestry data: {} and {} "
                      "deemed parents of {}"
                      .format(parent[prev], pid, prev))
                exit()
            parent[prev] = pid
        prev = pid

reach = transitive_closure(graph)

events = []
for line in open(sys.argv[4]):
    events.append(tuple(line.split()))

for i, j in itertools.combinations(events, 2):
    type_i, pid_i, path_i = i
    type_j, pid_j, path_j = j
    if i == j:
        continue
    if path_i != path_j:
        continue
    # Ignore WW conflicts for now (and RR):
    if type_i == type_j:
        continue
    t_i = get_target(pid_i)
    t_j = get_target(pid_j)
    if not reach[t_i][t_j] and not reach[t_j][t_i]:
        print("race detected: {}/{} access to file {} from {} and {}"
              .format(type_i, type_j, path_i, t_i, t_j))
