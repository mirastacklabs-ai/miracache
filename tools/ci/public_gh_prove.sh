#!/usr/bin/env bash
# Proves the GitHub workflow steps (tools/ci/public/overlay/.github/scripts/ci.sh) on a clean ubuntu:24.04:
#   tools/ci/public_gh_prove.sh [--sha REV]
# Exports the public tree of REV (no gitleaks, no build), adds tests/python for the Python step, copies it into an
# ubuntu:24.04 container (docker cp: works with a remote docker daemon), and runs deps, release build, Go, Python,
# ruff, packaging and the release-notes step there. For the workbench job: `workbench.sh --host`.
# Last line "OK: ..." or "FAIL: ...".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
rev=HEAD
[[ ${1:-} == --sha ]] && rev=$2
out=build/pubcheck-gh
tools/ci/public_export.sh --sha "$rev" --out "$out" --no-secret-scan | tail -1
mkdir -p "$out/tests"
git archive "$(git rev-parse "$rev")" tests/python | tar -x -C "$out"
mkdir -p build/workbench
cid=$(docker create --cpus 4 --memory 8g ubuntu:24.04 bash /prove.sh)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
cat > build/prove-inner.sh <<'EOS'
set -euo pipefail
cd /work
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq --no-install-recommends curl python3-venv gcc libc6-dev >/dev/null
echo "=== deps"; .github/scripts/ci.sh deps >/dev/null
curl -fsSL https://go.dev/dl/go1.27.4.linux-amd64.tar.gz -o /tmp/go.tgz
echo "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840  /tmp/go.tgz" | sha256sum -c
tar -C /usr/local -xzf /tmp/go.tgz
export PATH=/usr/local/go/bin:$PATH GOFLAGS=-buildvcs=false HOME=/tmp
echo "=== build release"; .github/scripts/ci.sh build release || { grep -n -B3 -A30 "pthread" /work/build/release/CMakeFiles/CMakeConfigureLog.yaml | tail -120; exit 1; }
echo "=== go"; .github/scripts/ci.sh go
echo "=== python"; .github/scripts/ci.sh python
echo "=== ruff"; python3 -m venv /tmp/rv; /tmp/rv/bin/pip install -q ruff==0.14.5; PATH=/tmp/rv/bin:$PATH .github/scripts/ci.sh ruff
echo "=== package"; .github/scripts/ci.sh package alpha-0.0.0
echo "=== notes"; printf '# C\n\n## alpha-0.0.0\n\nhello\n\n## alpha-0.0.1\n\nnope\n' > CHANGELOG.md; .github/scripts/ci.sh notes alpha-0.0.0
echo "OK: ubuntu steps"
EOS
docker cp "$out" "$cid:/work"
docker cp build/prove-inner.sh "$cid:/prove.sh"
if docker start -a "$cid" 2>&1 | tee build/workbench/gh-prove.log | tail -60; then :; fi
grep -q '^OK: ubuntu steps' build/workbench/gh-prove.log || { echo "FAIL: public gh prove"; exit 1; }
echo "OK: public gh prove ($rev)"
