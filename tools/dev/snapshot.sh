#!/usr/bin/env bash
# Push a snapshot of the working tree (tracked changes + untracked, non-ignored files) to
# origin/backup/wip-<branch>, without touching the index, the working tree or the branch.
# Safe to run while agents are editing. Usage: tools/dev/snapshot.sh [repo-dir]
set -euo pipefail
cd "${1:-$(dirname "${BASH_SOURCE[0]}")/../..}"
branch=$(git rev-parse --abbrev-ref HEAD)
tmp_index=$(mktemp); trap 'rm -f "$tmp_index"' EXIT
cp "$(git rev-parse --git-dir)/index" "$tmp_index"
GIT_INDEX_FILE=$tmp_index git add -A
tree=$(GIT_INDEX_FILE=$tmp_index git write-tree)
if [[ $tree == "$(git rev-parse 'HEAD^{tree}')" ]]; then echo "snapshot: clean, nothing to push"; exit 0; fi
commit=$(git commit-tree "$tree" -p HEAD -m "wip snapshot of $branch $(date -u +%FT%TZ)")
git push -q -f origin "$commit:refs/heads/backup/wip-$branch"
echo "snapshot: $commit -> origin/backup/wip-$branch"
