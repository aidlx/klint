#!/usr/bin/env bash
set -euo pipefail

find src -type f \( -name "*.hpp" -o -name "*.cpp" \) -print0 | \
  xargs -0 clang-format -i -style=LLVM
