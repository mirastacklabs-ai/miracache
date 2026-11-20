#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs ONE heavy command on the GitLab runner (the on-demand `workbench` job of .gitlab-ci.yml) instead of the Mac,
# waits for it and fetches its logs. Heavy runs go to the CI runner, not the Mac.
#
#   tools/ci/workbench.sh --ref backup/<name> [--tsan] [--host] [--cpus N] [--mem SIZE] [--no-wait] -- 'COMMAND'
#   tools/ci/workbench.sh --cancel <pipeline id>    cancel a run and delete its throwaway branch
#   tools/ci/workbench.sh --prune                   delete throwaway branches whose pipelines have all ended
#
#   --ref       the pushed backup/* branch whose code runs (pushing one starts no pipeline). Only backup/*: a workbench
#               pipeline on a task/* or main sha would look like (or hide) that sha's gate. Default: the current branch.
#   --tsan      run in the ThreadSanitizer-capable dev container (tools/dev/run.sh --tsan; asan runs need it too).
#               RDMA is refused: the runner has no RDMA, and RDMA runs stay on the Mac.
#   --host      run COMMAND in the job shell (docker CLI) instead of the dev container: for steps that start containers
#               themselves (tools/ci/engine_contract.sh, the docker e2e without RDMA). Unbounded: no --cpus/--mem.
#   --cpus/--mem  the dev container's limits on the shared 8 CPU / 16 GB runner: 1..6 CPUs, at most 12g (default 4 / 8g).
#   --no-wait   print the pipeline id and exit; the throwaway branch stays until --cancel or --prune.
#
# How it works (the project does not let users set pipeline variables, and none are needed): the command and options are
# committed as .workbench/cmd and .workbench/opts on top of the ref's tip (git plumbing: your working tree, index and
# branch are untouched), pushed to a throwaway backup/wb/<name>/<time>-<n> branch (backup/* pushes start no pipeline),
# and an api pipeline is started there; only the workbench job runs in it (`exists: .workbench/cmd`; no gate runs on
# backup/*). After the run the logs are fetched and the throwaway branch is deleted (only names under backup/wb/ are
# ever deleted, by this script, without asking: they are its own). COMMAND is ONE quoted string and reaches bash byte
# for byte as a file (`bash .workbench/cmd`): its exit status is that of its LAST command, so chain steps with && or
# start it with `set -euo pipefail;`. It starts from a fresh checkout: configure and build what it needs, and keep only
# logs under build/workbench/ (the artifacts; no core dumps or build trees). Never put a secret in it: it is in git,
# the job log and the artifacts (14 days).
#
# Exit: 0 the command passed; 1 it failed, or the pipeline failed/was canceled; 2 usage or setup error (nothing left
# running); 3 the pipeline may still be running (wait cap of 9 h, or GitLab unreachable): the line names its id and
# branch. The last line is "OK: workbench <id>" or "FAIL: workbench ...", so ONE standard waiter fits a backgrounded run:
#   until grep -qE "^OK: |^FAIL" log || ! pgrep -f "[w]orkbench.sh"; do sleep 30; done
# Logs land in build/workbench/<pipeline id>/build/workbench/ at the repo top (console.log + whatever the command wrote).
set -euo pipefail

PROJECT=88734900  # gitlab.com mirastacklabs/miracache
WB_PREFIX=backup/wb/
die() { echo "FAIL: workbench: $*" >&2; exit 2; }
need() { [[ $1 -ge 2 ]] || die "$2 needs a value"; }
errf=$(mktemp "${TMPDIR:-/tmp}/workbench-err.XXXXXX")
idx=""
trap 'rm -f "$errf" ${idx:+"$idx"}' EXIT
# glab api with stderr kept OUT of the JSON (an update notice on stderr must not break jq).
api() { glab api "$@" 2>"$errf"; }
api_err() { head -c 300 "$errf" | tr '\n' ' '; }

command -v glab >/dev/null || die "glab is not installed (brew install glab; glab auth login)"
command -v jq >/dev/null || die "jq is not installed (brew install jq)"
cd "$(git rev-parse --show-toplevel)" || die "not inside the miracache checkout"

delete_branch() {  # $1: a throwaway branch name; refuses anything outside backup/wb/
  [[ $1 == "$WB_PREFIX"* ]] || { echo "workbench: refusing to delete $1 (not under $WB_PREFIX)" >&2; return 1; }
  if git push -q origin --delete "$1" 2>"$errf"; then return 0; fi
  echo "workbench: note: could not delete $1: $(api_err) (git push origin --delete $1)" >&2
  return 1
}

ref="" flags="" host=0 cpus="" mem="" wait=1
while [[ $# -gt 0 ]]; do
  case $1 in
    --ref) need $# --ref; ref=$2; shift 2 ;;
    --tsan) flags=--tsan; shift ;;
    --flags) need $# --flags; [[ $2 == --tsan ]] || die "--flags '$2' refused: only --tsan (RDMA runs stay on the Mac)"; flags=--tsan; shift 2 ;;
    --host) host=1; shift ;;
    --cpus) need $# --cpus; [[ $2 =~ ^[1-6]$ ]] || die "--cpus must be 1..6 (the runner is shared)"; cpus=$2; shift 2 ;;
    --mem)
      need $# --mem
      if [[ $2 =~ ^([1-9][0-9]*)g$ ]] && (( BASH_REMATCH[1] <= 12 )); then mem=$2
      elif [[ $2 =~ ^([1-9][0-9]*)m$ ]] && (( BASH_REMATCH[1] <= 12288 )); then mem=$2
      else die "--mem must be 1g..12g or 1m..12288m (the runner is shared)"; fi
      shift 2 ;;
    --no-wait) wait=0; shift ;;
    --cancel)
      need $# --cancel; [[ $2 =~ ^[0-9]+$ ]] || die "--cancel needs a pipeline id"
      resp=$(api -X POST "projects/$PROJECT/pipelines/$2/cancel") || die "cancel of $2 failed: $(api_err)"
      echo "workbench: pipeline $2: $(jq -r '.status // "?"' <<<"$resp")"
      b=$(jq -r '.ref // empty' <<<"$resp")
      if [[ $b == "$WB_PREFIX"* ]]; then delete_branch "$b" && echo "workbench: deleted $b"; fi
      exit 0 ;;
    --prune)
      n=0
      while read -r _ r; do
        b=${r#refs/heads/}
        pipes=$(api "projects/$PROJECT/pipelines?ref=$(jq -rn --arg b "$b" '$b|@uri')&per_page=20") || { echo "workbench: skip $b: $(api_err)" >&2; continue; }
        live=$(jq '[.[] | select(.status | IN("created","pending","waiting_for_resource","preparing","scheduled","running","canceling","waiting_for_callback"))] | length' <<<"$pipes")
        [[ $live == 0 ]] || { echo "workbench: keep $b (a pipeline is still live)"; continue; }
        delete_branch "$b" && { echo "workbench: deleted $b"; n=$((n + 1)); }
      done < <(git ls-remote origin "refs/heads/${WB_PREFIX}*")
      echo "OK: workbench prune: $n deleted"
      exit 0 ;;
    --) shift; break ;;
    -h|--help) sed -n '3,36p' "$0"; exit 0 ;;
    *) die "unknown option $1 (the command goes after --, as ONE quoted string)" ;;
  esac
done
[[ $# -eq 1 && -n $1 ]] || die "give the command as ONE quoted string after -- (got $# words)"
cmd=$1
[[ $host -eq 0 || -z $flags ]] || die "--tsan is a dev-container flag; it does not apply with --host"
[[ $host -eq 0 || ( -z $cpus && -z $mem ) ]] || die "--cpus/--mem limit the dev container; a --host run has no limits"
[[ -n $ref ]] || ref=$(git rev-parse --abbrev-ref HEAD)
[[ $ref =~ ^backup/[A-Za-z0-9._/-]+$ && $ref != backup/wb && $ref != "$WB_PREFIX"* ]] ||
  die "ref '$ref' refused: the workbench runs only your backup/* branches (git push origin HEAD:backup/<name>)"
git var GIT_COMMITTER_IDENT >/dev/null 2>&1 || die "git has no committer identity: set user.name and user.email"

# The job runs what is on origin: say exactly which commit that is, and refuse a branch whose local tip is unpushed.
ls_out=$(git ls-remote origin "refs/heads/$ref" 2>"$errf") || die "cannot reach origin: $(api_err)"
base=$(cut -f1 <<<"$ls_out")
[[ $base =~ ^[0-9a-f]{40}$ ]] || die "branch $ref is not on origin: push it first (git push origin HEAD:$ref)"
if [[ $ref == "$(git rev-parse --abbrev-ref HEAD)" && $(git rev-parse HEAD) != "$base" ]]; then
  die "local $ref ($(git rev-parse --short HEAD)) differs from origin ($(cut -c1-7 <<<"$base")): push it first"
fi
if ! git cat-file -e "$base^{tree}" 2>/dev/null; then
  git fetch -q origin "$base" 2>/dev/null || git fetch -q origin "refs/heads/$ref" 2>"$errf" || die "cannot fetch $ref: $(api_err)"
  git cat-file -e "$base^{tree}" 2>/dev/null || die "commit $(cut -c1-8 <<<"$base") of $ref is not available locally after a fetch"
fi

# The run commit: the ref's tree + .workbench/cmd + .workbench/opts, built on a temporary index.
opts=""
if [[ -n $flags ]]; then opts+="flags=$flags"$'\n'; fi
if [[ $host -eq 1 ]]; then opts+="host=1"$'\n'; fi
if [[ -n $cpus ]]; then opts+="cpus=$cpus"$'\n'; fi
if [[ -n $mem ]]; then opts+="mem=$mem"$'\n'; fi
idx=$(mktemp "${TMPDIR:-/tmp}/workbench-index.XXXXXX")
{
  GIT_INDEX_FILE=$idx git read-tree "$base" &&
  cmd_blob=$(printf '%s\n' "$cmd" | git hash-object -w --stdin) &&
  opts_blob=$(printf '%s' "$opts" | git hash-object -w --stdin) &&
  GIT_INDEX_FILE=$idx git update-index --add --cacheinfo "100644,$cmd_blob,.workbench/cmd" --cacheinfo "100644,$opts_blob,.workbench/opts" &&
  tree=$(GIT_INDEX_FILE=$idx git write-tree) &&
  run_commit=$(git commit-tree "$tree" -p "$base" -m "workbench run (never merge): ${cmd:0:72}")
} 2>"$errf" || die "building the run commit failed: $(api_err)"
rm -f "$idx"; idx=""
wb_branch="${WB_PREFIX}${ref#backup/}/$(date -u +%Y%m%dT%H%M%SZ)-$$"
git push -q origin "$run_commit:refs/heads/$wb_branch" 2>"$errf" || die "push of $wb_branch failed: $(api_err)"
# From here a stop must clean up (or name) the branch.
trap 'rm -f "$errf"; echo; delete_branch "$wb_branch" >/dev/null 2>&1 || echo "workbench: $wb_branch left; delete it with --prune" >&2; exit 130' INT TERM

resp=$(api -X POST "projects/$PROJECT/pipeline?ref=$(jq -rn --arg b "$wb_branch" '$b|@uri')") || {
  delete_branch "$wb_branch" || true
  die "the pipeline was not created: $(api_err) $resp"
}
pid=$(jq -r '.id // empty' <<<"$resp" 2>/dev/null) || pid=""
if ! [[ $pid =~ ^[0-9]+$ ]]; then
  # The POST succeeded but its answer did not parse: look the pipeline up by its ref and cancel it, so no orphan runs.
  pid=$(api "projects/$PROJECT/pipelines?ref=$(jq -rn --arg b "$wb_branch" '$b|@uri')" | jq -r '.[0].id // empty' 2>/dev/null) || pid=""
  if [[ $pid =~ ^[0-9]+$ ]]; then api -X POST "projects/$PROJECT/pipelines/$pid/cancel" >/dev/null || true; fi
  delete_branch "$wb_branch" || true
  die "the pipeline answer did not parse${pid:+ (pipeline $pid canceled)}: $(head -c 200 <<<"$resp")"
fi
echo "workbench: pipeline $pid: $ref @ $(cut -c1-8 <<<"$base") + run commit $(cut -c1-8 <<<"$run_commit") on $wb_branch: $(jq -r .web_url <<<"$resp")"
if [[ $wait -eq 0 ]]; then
  echo "OK: workbench $pid started (branch $wb_branch stays until: tools/ci/workbench.sh --cancel $pid, or --prune once it ended)"
  exit 0
fi
trap 'rm -f "$errf"; echo; echo "FAIL: workbench $pid: stopped waiting; it keeps running on $wb_branch (tools/ci/workbench.sh --cancel $pid)" >&2; exit 130' INT TERM

# One waiter. Queued states (created, pending, waiting_for_resource behind a gate, preparing, scheduled), running and the
# in-between states (canceling, waiting_for_callback) keep it going; every other state ends it. A failed API call is
# retried; 10 in a row end the wait (exit 3: the pipeline may still run).
st="" errs=0
deadline=$(( $(date +%s) + 9 * 3600 ))
while :; do
  if out=$(api "projects/$PROJECT/pipelines/$pid") && st=$(jq -r '.status // empty' <<<"$out" 2>/dev/null) && [[ -n $st ]]; then
    errs=0
  else
    errs=$((errs + 1)); st=""
    if (( errs >= 10 )); then
      echo "FAIL: workbench $pid: GitLab API failed 10 times in a row ($(api_err)); it may still run on $wb_branch (tools/ci/workbench.sh --cancel $pid)" >&2
      exit 3
    fi
  fi
  case $st in
    ""|created|pending|waiting_for_resource|preparing|scheduled|running|canceling|waiting_for_callback) ;;
    *) break ;;
  esac
  if (( $(date +%s) >= deadline )); then
    echo "FAIL: workbench $pid still ${st:-unknown} after 9 h on $wb_branch (tools/ci/workbench.sh --cancel $pid)" >&2
    exit 3
  fi
  sleep 30
done
trap 'rm -f "$errf"; echo "FAIL: workbench $pid: interrupted while fetching logs; $wb_branch left (--prune)" >&2; exit 130' INT TERM

out_dir=build/workbench/$pid
mkdir -p "$out_dir"
fetched=0
job=$(api "projects/$PROJECT/pipelines/$pid/jobs" | jq -r '[.[] | select(.name == "workbench")][0].id // empty' 2>/dev/null) || job=""
if [[ -n $job ]] && api "projects/$PROJECT/jobs/$job/artifacts" > "$out_dir/artifacts.zip" &&
   unzip -q -o "$out_dir/artifacts.zip" -d "$out_dir" 2>/dev/null; then
  rm -f "$out_dir/artifacts.zip"
  fetched=1
  if [[ -f $out_dir/build/workbench/console.log ]]; then tail -n 5 "$out_dir/build/workbench/console.log"; fi
  echo "workbench: logs in $out_dir/build/workbench/"
else
  echo "workbench: no artifacts fetched for pipeline $pid (job ${job:-missing}); see the job page" >&2
fi
# The pipeline, its job log and its artifacts stay on GitLab; only the throwaway branch goes. Kept when the logs could not
# be fetched (a retry from the web UI still finds its commit); --prune removes it later.
if [[ $fetched -eq 1 ]]; then delete_branch "$wb_branch" || true; else echo "workbench: kept $wb_branch (no logs fetched; --prune later)" >&2; fi
if [[ $st == success ]]; then echo "OK: workbench $pid"; else echo "FAIL: workbench $pid $st"; exit 1; fi
