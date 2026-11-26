#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
minbucket="${MINBUCKET_ROOT:-$root/../MinBucket-MPSI}"
prefix="${DEPENDENCY_PREFIX:-$minbucket/.runtime/prefix}"
export LD_LIBRARY_PATH="$prefix/usr/lib/x86_64-linux-gnu:$prefix/lib:$prefix/lib64:${LD_LIBRARY_PATH:-}"
cmake -S "$root" -B "$root/build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$prefix;$prefix/usr" -DMINBUCKET_ROOT="$minbucket" \
  -DEZPC_ROOT="${EZPC_ROOT:-$root/../EzPC}"
cmake --build "$root/build" --parallel "${BUILD_JOBS:-4}"
ctest --test-dir "$root/build" --output-on-failure
