## What this changes

<!-- What and why, in a few sentences. Link the issue it fixes or the discussion it follows. -->

Fixes #

## How it was tested

<!-- Which builds and tests you ran, and on what (soft-RoCE, soft-iWARP, hardware NIC; engine version if relevant). -->

- [ ] `cmake --preset release && cmake --build --preset release` builds without warnings
- [ ] the relevant tests pass (name them below)
- [ ] new behaviour has new tests

```
```

## Checklist

- [ ] Every commit is signed off (`git commit -s`): the [DCO 1.1](https://developercertificate.org/) applies, see `CONTRIBUTING.md`
- [ ] Code is formatted with `.clang-format`; new source files start with `// SPDX-License-Identifier: Apache-2.0`
- [ ] Wire or storage format changes: discussed in an issue first, `static_assert`s and golden vectors in `proto/golden/` updated
- [ ] New dependencies are Apache-2.0, MIT or BSD licensed, with pinned versions and hashes
- [ ] User-facing changes are noted in `CHANGELOG.md` under "Unreleased"
- [ ] No secrets, keys, certificates or private addresses in the change
