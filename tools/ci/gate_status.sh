#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Is this commit gated? `main` is fast-forwarded only to a sha for which this prints "OK: gate ..." (exit 0).
#
#   tools/ci/gate_status.sh [<sha or ref>]     (default HEAD)
#
# Gated = some pipeline of that exact sha has a `gate` JOB that succeeded, and every `gate-rdma` job of that pipeline
# succeeded too; OR (user, 2026-11-18) its nearest gated first-parent ancestor has the SAME product code
# (tools/ci/product-paths.txt): a commit that changes only docs, release scripts or the CI release jobs re-tests nothing.
set -euo pipefail
PROJECT=88734900  # gitlab.com mirastacklabs/miracache
command -v glab >/dev/null || { echo "FAIL: gate_status: glab is not installed" >&2; exit 2; }
command -v jq >/dev/null || { echo "FAIL: gate_status: jq is not installed" >&2; exit 2; }
cd "$(git rev-parse --show-toplevel)"
sha=$(git rev-parse --verify "${1:-HEAD}^{commit}" 2>/dev/null) || { echo "FAIL: gate_status: no such commit: ${1:-HEAD}" >&2; exit 2; }
short=$(cut -c1-8 <<<"$sha")

# exact SHA: prints "OK <pipeline id>" when a gate (and every gate-rdma) of that SHA succeeded, else "NO <what was seen>".
# Returns 2 on an API error (the caller exits 2: an error is never "not gated").
exact() {
  local pipes ids id jobs gate rdma_bad seen=""
  pipes=$(glab api "projects/$PROJECT/pipelines?sha=$1&per_page=50" 2>&1) || { echo "$pipes" >&2; return 2; }
  ids=$(jq -r '.[].id' <<<"$pipes" 2>/dev/null) || { echo "$pipes" >&2; return 2; }
  for id in $ids; do
    jobs=$(glab api "projects/$PROJECT/pipelines/$id/jobs?per_page=100" 2>&1) || { echo "$jobs" >&2; return 2; }
    gate=$(jq -r '[.[] | select(.name == "gate")][0].status // empty' <<<"$jobs")
    [[ -n $gate ]] || continue  # a workbench or release pipeline: never a gate
    rdma_bad=$(jq -r '[.[] | select(.name == "gate-rdma" and .status != "success")] | length' <<<"$jobs")
    if [[ $gate == success && $rdma_bad == 0 ]]; then echo "OK $id"; return 0; fi
    seen="$seen pipeline $id: gate $gate$([[ $rdma_bad != 0 ]] && echo ", gate-rdma not green");"
  done
  echo "NO$seen"
}
ask() { local out; out=$(exact "$1") || { echo "FAIL: gate_status: API error" >&2; exit 2; }; echo "$out"; }

r=$(ask "$sha")
if [[ $r == OK* ]]; then echo "OK: gate $short pipeline ${r#OK }"; exit 0; fi
seen=${r#NO}
paths=(); while IFS= read -r p; do paths+=("$p"); done < <(grep -vE "^[[:space:]]*(#|$)" tools/ci/product-paths.txt)  # bash 3 (macOS): no mapfile
for anc in $(git rev-list --first-parent --max-count=200 "$sha^" 2>/dev/null); do
  a=$(ask "$anc")
  [[ $a == OK* ]] || continue
  if git diff --quiet "$anc" "$sha" -- "${paths[@]}"; then
    echo "OK: gate $short (product code identical to gated $(cut -c1-8 <<<"$anc"), pipeline ${a#OK })"
    exit 0
  fi
  echo "FAIL: gate $short not gated: product code differs from the nearest gated ancestor $(cut -c1-8 <<<"$anc");$seen"
  exit 1
done
echo "FAIL: gate $short not gated:${seen:- no gate pipeline for this sha or a gated ancestor}"
exit 1
