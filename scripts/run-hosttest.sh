#!/usr/bin/env bash
# Host-side unit tests.
#
# policy.c is compiled against the linux/* shims in scripts/hosttest/ and checked against every
# configured (caller, target) pair: catches C-level mistakes the Python model cannot see (word
# sizes, ordering, field mixups).
#
# The ABX reader is C++ and self-contained, so its test is built and run here too, against the
# first bytes of a real packages.xml.
set -eu
cd "$(dirname "$0")/.."

out=build/policy_host_test
cc -O1 -g -I src -I scripts/hosttest -I src/include -o "$out" scripts/policy_host_test.c
"$out"

abx=build/abx_reader_test
c++ -std=c++23 -O1 -I src/tools -o "$abx" scripts/abx_reader_test.cpp src/tools/abx.cpp
"$abx"

paths=build/rule_sources_test
c++ -std=c++23 -O1 -I src/tools -o "$paths" scripts/rule_sources_test.cpp src/tools/paths.cpp
"$paths" build/rule_sources_test.d

# Both rule formats: what each one does with the same package list, driven with configs instead of
# a device.
paging=build/paging_test
c++ -std=c++23 -O1 -I src/tools -o "$paging" scripts/paging_test.cpp src/tools/paging.cpp -lz
"$paging"

rules=build/rules_test
c++ -std=c++23 -O1 -I src/tools -o "$rules" scripts/rules_test.cpp src/tools/rules.cpp \
  src/tools/paths.cpp src/tools/packages.cpp src/tools/abx.cpp
"$rules"
