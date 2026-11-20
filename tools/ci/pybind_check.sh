#!/usr/bin/env bash
# Runs INSIDE the dev container (tools/dev/run.sh -- tools/ci/pybind_check.sh): the Python-binding tail of
# tools/ci/build_and_test.sh on its own. Tests the binding against the already built build/dev/client/libmiracache.so,
# then builds the wheel and runs the round-trip test from the unpacked wheel. tools/ci/full_gate.sh no longer calls it:
# the devrel lane's build_and_test.sh dev release already runs this same binding + wheel step as part of its tail (R07).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dev_lib=build/dev/client/libmiracache.so
[[ -f $dev_lib ]] || { echo "FAIL: $dev_lib missing (build the dev preset first)"; exit 1; }
MIRACACHE_LIB=$PWD/$dev_lib PYTHONPATH=python python3 -m unittest discover -s tests/python -v
rm -rf build/wheel build/wheel-unpacked
python3 tools/pkg/build_wheel.py --lib "$dev_lib" --out build/wheel
python3 -m zipfile -e build/wheel/miracache-*.whl build/wheel-unpacked
PYTHONPATH=build/wheel-unpacked python3 -m unittest discover -s tests/python -p 'test_roundtrip.py' -v
echo "OK: python binding + wheel"
