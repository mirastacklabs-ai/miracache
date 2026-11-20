#!/usr/bin/env bash
# Fails if code under core/ (and sim/, client/) reads wall-clock time, entropy, sleeps, spawns
# threads, or uses iteration-order-unstable containers/hashes outside util/clock.* and
# util/random.* (spec 14.3: all time and randomness go through Clock and Random).
# Usage: lint_nondeterminism.sh [dir...]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

dirs=("$@"); [[ ${#dirs[@]} -eq 0 ]] && dirs=(core sim client server)

# Time, entropy, sleeping.
pattern='std::chrono::(system_clock|steady_clock|high_resolution_clock)|random_device|(^|[^[:alnum:]_.>])(::|std::)?(rand|srand|time|sleep|usleep|nanosleep)[[:space:]]*\(|sleep_for|sleep_until|clock_gettime|gettimeofday'
# Non-deterministic generators and entropy sources.
pattern+='|mt19937|default_random_engine|minstd_rand|ranlux|getrandom|/dev/u?random|arc4random'
# The OS CSPRNG is reachable from exactly one file (core/util/nonce_source.cpp, allow-listed below).
pattern+='|RAND_bytes|RAND_priv_bytes|RAND_pseudo_bytes'
# Scheduling-dependent execution.
pattern+='|std::this_thread|std::thread|std::jthread|std::async|pthread_create|condition_variable'
# Hash-order or address-order dependent iteration.
pattern+='|unordered_|std::hash'
pattern+='|(map|set|multimap|multiset)[[:space:]]*<[^,<>;]*\*[[:space:]]*[,>]'

# grep exits 1 for "no match" (fine) and >=2 for real errors (fatal).
set +e
raw=$(grep -rnE --include='*.h' --include='*.hpp' --include='*.cpp' --include='*.cc' -e "$pattern" "${dirs[@]}")
rc=$?
set -e
if [[ $rc -gt 1 ]]; then
  echo "lint_nondeterminism: grep failed (exit $rc)" >&2
  exit 2
fi

hits=""
if [[ -n $raw ]]; then
  # Drop the allow-listed implementation files and pure comment lines.
  # client/runtime/ is the only client/ code allowed threads, on lines carrying // lint:client-runtime.
  # The verbs_cm backend runs on real hardware; its async-event dispatcher needs one thread.
  # Only lines of that file carrying the marker comment are allowed, nothing else there.
  hits=$(printf '%s\n' "$raw" \
    | { grep -vE '^core/util/(clock|random)\.(h|cpp):' || [[ $? -eq 1 ]]; } \
    | { grep -vE '^core/util/nonce_source\.cpp:' || [[ $? -eq 1 ]]; } \
    | { grep -vE '^core/fabric/verbs_cm/verbs_cm_fabric\.cpp:[0-9]+:.*(std::thread|pthread_create).*// lint:dispatcher-thread$' || [[ $? -eq 1 ]]; } \
    | { grep -vE '^client/runtime/[^:]+:[0-9]+:.*(std::thread|std::jthread|condition_variable).*// lint:client-runtime$' || [[ $? -eq 1 ]]; } \
    | { grep -vE '^server/runtime/[^:]+:[0-9]+:.*(std::thread|std::jthread|condition_variable).*// lint:server-runtime$' || [[ $? -eq 1 ]]; } \
    | { grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' || [[ $? -eq 1 ]]; })
fi

if [[ -n $hits ]]; then
  echo "nondeterminism lint failed: use Clock/Random and ordered containers instead:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "lint_nondeterminism: ok (${dirs[*]})"
