#!/usr/bin/env bash
# Build the miracache wheel as an artifact: build/wheel/miracache-<ver>-py3-none-<platform>.whl
#   tools/dev/run.sh -- tools/pkg/build_wheel.sh [preset]        (preset default: release; "dev" is faster to build)
# The version source of truth is pyproject.toml. This script refuses to build when CMakeLists.txt or a
# miracache==X pin in deploy/agentbench/*.json disagrees with it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
preset=${1:-release}

ver=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' pyproject.toml | head -n1)
cmake_ver=$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
[[ -n $ver ]] || { echo "FAIL: no version in pyproject.toml" >&2; exit 1; }
[[ $cmake_ver == "$ver" ]] || { echo "FAIL: CMakeLists.txt says $cmake_ver, pyproject.toml says $ver" >&2; exit 1; }
for f in deploy/agentbench/*.json; do
  pin=$(sed -n 's/.*"pip_extras": *"miracache==\([^"]*\)".*/\1/p' "$f")
  [[ -z $pin || $pin == "$ver" ]] || { echo "FAIL: $f pins miracache==$pin, pyproject.toml says $ver" >&2; exit 1; }
done

export CMAKE_BUILD_PARALLEL_LEVEL=${CMAKE_BUILD_PARALLEL_LEVEL:-2}
cmake --preset "$preset" >/dev/null
cmake --build --preset "$preset" --target miracache_shared
lib=build/$preset/client/libmiracache.so
[[ -f $lib ]] || { echo "FAIL: $lib not built" >&2; exit 1; }
rm -f build/wheel/miracache-"$ver"-*.whl
python3 tools/pkg/build_wheel.py --lib "$lib" --out build/wheel
echo "OK: wheel miracache==$ver in build/wheel (install: pip install --no-index --find-links build/wheel miracache==$ver)"
