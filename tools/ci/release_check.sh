#!/usr/bin/env bash
# The release promotion chain (workstation setup guide, releases section), checked by the CI job `release-check` of a tag pipeline:
#   dev-X.Y.Z -> qa-X.Y.Z -> mark-X.Y.Z -> alpha-X.Y.Z | beta-X.Y.Z | ga-X.Y.Z
#   internal (GitLab only)                public (published to GitHub)
# tools/ci/release_check.sh TAG SHA
#   - TAG is <stage>-MAJOR.MINOR.PATCH and SHA (the tagged commit) is on main;
#   - nothing re-tests: the commit was gated on its way into main (test once, promote the same build); every later stage must sit on the SAME commit as the
#     previous stage's tag of the same version, and that tag's pipeline must have gone green. Green is a marker tag
#     ok/<previous tag> on that same commit: the job `release-record` pushes it (job token) only when every earlier job
#     of that pipeline passed. Release tags and markers are protected (*.*.*): only a Maintainer's pipeline makes them,
#     and a marker names its commit, so a tag deleted and re-created elsewhere never inherits it. (The GitLab artifacts
#     API is not open to the job token on this tier, run #346.)
# Read-only; runs on a workstation too. Last line "OK: release ..." or "FAIL: release ...".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
tag=${1:?usage: tools/ci/release_check.sh TAG SHA} sha=${2:?usage: tools/ci/release_check.sh TAG SHA}
fail() { echo "FAIL: release $tag: $*"; exit 1; }

[[ $tag =~ ^(dev|qa|mark|alpha|beta|ga)-([0-9]+\.[0-9]+\.[0-9]+)$ ]] \
  || fail "not a release tag: <dev|qa|mark|alpha|beta|ga>-MAJOR.MINOR.PATCH, e.g. dev-0.1.0"
stage=${BASH_REMATCH[1]} ver=${BASH_REMATCH[2]}
case $stage in
  dev) prev="" kind=internal ;;
  qa) prev=dev kind=internal ;;
  mark) prev=qa kind=internal ;;
  alpha|beta|ga) prev=mark kind=public ;;
esac
sha=$(git rev-parse --verify -q "$sha^{commit}") || fail "no commit $2"

git fetch -q origin main || fail "cannot fetch main"
git merge-base --is-ancestor "$sha" FETCH_HEAD || fail "${sha:0:8} is not on main (tag a commit of main)"

# Peeled commit of a remote tag, or empty (ls-remote errors fail).
remote_tag() {
  local out
  out=$(git ls-remote origin "refs/tags/$1" "refs/tags/$1^{}") || return 1  # the caller fails: fail() inside $(...) would be captured
  awk -v r="refs/tags/$1^{}" -v t="refs/tags/$1" '$2==r{p=$1} $2==t{c=$1} END{print (p!=""?p:c)}' <<<"$out"
}

if [[ -n $prev ]]; then
  ptag=$prev-$ver
  psha=$(remote_tag "$ptag") || fail "cannot read the tags of origin"
  [[ -n $psha ]] || fail "$ptag does not exist: tag $ptag on this commit first"
  [[ $psha == "$sha" ]] || fail "$ptag is on ${psha:0:8}, this tag on ${sha:0:8}: a promotion must tag the same commit"
  osha=$(remote_tag "ok/$ptag") || fail "cannot read the tags of origin"
  [[ -n $osha ]] || fail "the $ptag pipeline has not gone green (no ok/$ptag yet): wait for it, or fix and release a new version"
  [[ $osha == "$sha" ]] || fail "ok/$ptag marks ${osha:0:8}, not ${sha:0:8} (re-tagged?): release a new version"
fi
case $stage in
  dev) next="its code was gated on the way into main; tag qa-$ver on this commit" ;;
  qa) next="tag mark-$ver on this commit" ;;
  mark) next="tag alpha-$ver, beta-$ver or ga-$ver on this commit to publish it" ;;
  *) next="publish pushes this commit's public tree to GitHub as $tag" ;;
esac
echo "OK: release $tag ($kind) on ${sha:0:8}$([[ -n $prev ]] && echo ", promoted from green $prev-$ver"): $next"
