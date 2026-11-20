#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Promote ONE commit of main through the release chain dev -> qa -> mark -> alpha (workstation setup guide, releases):
#   tools/ci/release_chain.sh <full sha on main> <X.Y.Z> [alpha|beta|ga]
# Pushes each annotated tag, waits for its tag pipeline (90 min cap per stage: publish on the shared 8-vCPU runner takes
# ~30 min), checks the ok/<tag> marker that release-record pushes, then the next stage. Stops on the first failure.
# Run it in the background with no other waiter; its last line is "OK: released ..." or "FAIL: ...".
set -u
sha=${1:?usage: release_chain.sh <sha> <X.Y.Z> [alpha|beta|ga]} ver=${2:?version X.Y.Z} pub=${3:-alpha}
cd "$(git rev-parse --show-toplevel)" || exit 1
git merge-base --is-ancestor "$sha" origin/main 2>/dev/null || { git fetch -q origin; git merge-base --is-ancestor "$sha" origin/main; } \
  || { echo "FAIL: $sha is not on origin/main"; exit 1; }
P=88734900
for st in dev qa mark "$pub"; do
  t=$st-$ver
  git tag -a "$t" -m "miracache $t" "$sha" && git push -q origin "refs/tags/$t" || { echo "FAIL: push $t"; exit 1; }
  echo "pushed $t $(date +%H:%M:%S)"
  for i in $(seq 1 270); do
    sleep 20
    s=$(glab api "projects/$P/pipelines?ref=$t&per_page=1" 2>/dev/null | grep -o '"status":"[a-z_]*"' | head -1 | cut -d'"' -f4)
    case "$s" in
      success) echo "green $t $(date +%H:%M:%S)"; break ;;
      failed|canceled|skipped) echo "FAIL: $t pipeline $s"; exit 1 ;;
    esac
    [ "$i" = 270 ] && { echo "FAIL: $t timed out (status $s)"; exit 1; }
  done
  if [ "$st" != "$pub" ]; then
    git ls-remote --exit-code origin "refs/tags/ok/$t" >/dev/null || { echo "FAIL: no ok/$t marker"; exit 1; }
  fi
done
echo "OK: released $pub-$ver"
