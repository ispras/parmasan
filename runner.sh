#!/bin/bash -

function die()
{
    echo "$@"
    exit 1
}

trap ' if [ -n "$pushed" ]; then popd; fi ' EXIT

makefile=suffix.make
src=/mnt/co/trash/akme
target=all

# makefile=Makefile
# src=/mnt/co/trash/akme/test-proj/findlib-1.8.0
# src=/mnt/co/trash/akme/test-proj/lib-findlib
# target=opt

froot=/mnt/fuse # fuse mount point
# hardcoded paths
pidanc=/tmp/pidanc.log
fuselog=/tmp/fuse.log

mkdir -p /tmp/remake
rm -f /tmp/remake/*
rm -f "$fuselog" "$pidanc"

pushd /mnt/co/remake
pushed=true
make make || die "$0: cannot make remake"
mkdir -p /tmp/bin/
cp make remake /tmp/bin

cd "$src"
make -f "$makefile" clean

/mnt/co/libfuse/example/passthrough -s "$froot"

cd "$froot/$src" || die "$0: cannot cd into fuse-managed $src"
pwd
/tmp/bin/remake -f "$makefile"

fusermount3 -z -u "$froot" || die "$0: cannot unmount fuse fs"

cd /tmp/remake
"$(dirname "$0")/parmasan-offline.py" <(cat log.*) <(cat pid.*) "$pidanc" "$fuselog" |
    tee res.txt || die "$0: processing script failed"
