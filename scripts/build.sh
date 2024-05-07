#!/usr/bin/sh

cd target
cmake .. 2>&1 >/dev/null
make 2>&1 >/dev/null

./rdg

echo