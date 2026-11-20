#!/usr/bin/env bash
# The lab PKI script ships in the public tree (deploy/examples/lab-certs.sh: the tests use it); this path keeps every
# existing caller working: tools/dev/lab-certs.sh <out-dir> --nodes 1,2 --clients 1,2 [--days N]
exec "$(dirname "${BASH_SOURCE[0]}")/../../deploy/examples/lab-certs.sh" "$@"
