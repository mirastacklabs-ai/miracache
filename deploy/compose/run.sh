#!/usr/bin/env bash
# One command: build the images, start 3 memory nodes, run the test client, print PASS or FAIL, clean up.
#   deploy/compose/run.sh           exit 0 on PASS, 1 otherwise
# Needs a Linux host or VM with an rxe device (see setup-rxe.sh) and the open-source Docker engine + compose plugin.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose version >/dev/null 2>&1 || { echo "FAIL: the docker compose plugin is required"; exit 1; }
docker buildx version >/dev/null 2>&1 || { echo "FAIL: BuildKit is required (Ubuntu: apt-get install docker-buildx)"; exit 1; }
# Build the two images one at a time (each compile is heavy); the stack then starts without rebuilding.
docker compose build node1 || { echo "FAIL: building the memory node image"; exit 1; }
docker compose build client || { echo "FAIL: building the client image"; exit 1; }
docker compose down -v >/dev/null 2>&1
if ! docker compose up -d node1 node2 node3; then
  docker compose logs prepare node1 node2 node3 2>&1 | tail -40
  docker compose down -v >/dev/null 2>&1
  echo "FAIL: the memory nodes did not start"; exit 1
fi
log=$(mktemp)
docker compose run --rm client 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[[ $rc -eq 0 ]] || docker compose logs node1 node2 node3 2>&1 | tail -30
docker compose down -v >/dev/null 2>&1
if [[ $rc -eq 0 ]] && tail -n1 "$log" | grep -qx 'PASS'; then rm -f "$log"; exit 0; fi
rm -f "$log"
echo "FAIL: see the output above (client exit code $rc)"
exit 1
