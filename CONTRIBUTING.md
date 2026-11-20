# Contributing

## Developer Certificate of Origin
Every commit must be signed off (`git commit -s`), certifying the
[DCO 1.1](https://developercertificate.org/): you wrote the change or have the right to submit it
under Apache-2.0. The sign-off line is `Signed-off-by: Your Name <you@example.com>`.

## Rules
- Protocol or layout changes need a design discussion in an issue first.
- C++20, `-Wall -Wextra -Werror`, formatted with `.clang-format`. No exceptions on the data path; use `Expected<T, Error>`.
- All time and randomness go through `Clock` and `Random`.
- Every wire or storage struct has `static_assert`s on size and offsets, and golden vectors in `proto/golden/`.
- Source files start with `// SPDX-License-Identifier: Apache-2.0`.
- Licences of dependencies: Apache-2.0, MIT or BSD only; pin versions and hashes.

## Before you open a pull request
```sh
cmake --preset release -DMIRACACHE_SIM=OFF && cmake --build --preset release && ctest --preset release -LE rdma -j"$(nproc)"
(cd controller && go vet ./... && go test -race ./...)
PYTHONPATH=python python3 -m unittest discover -s tests/python
```
Changes to the protocol, the store or placement should also pass a simulator sweep (`cmake --preset sim`, see
`docs/simulator.md`).
