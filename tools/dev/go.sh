#!/usr/bin/env bash
# The pinned Go toolchain lives in deploy/docker/go.sh (the controller image builds with it, and it ships in the public
# tree); this path keeps every existing caller working: tools/dev/run.sh -- tools/dev/go.sh [-C dir] <go args...>
exec "$(dirname "${BASH_SOURCE[0]}")/../../deploy/docker/go.sh" "$@"
