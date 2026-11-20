# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue or pull request. Use either:

- **GitHub private vulnerability reporting**: the "Report a vulnerability" button under this repository's
  **Security** tab, or
- **email**: [cache@mirastacklabs.ai](mailto:cache@mirastacklabs.ai), with "security" in the subject.

Please include:

- the miracache version (release tag or commit) and how it was built or installed (systemd, Docker);
- the component involved (`mira-memnode`, `libmiracache`, the vLLM or SGLang adapter, `mira-controller`, `mirctl`,
  `mira-preflight`, `node_prep`);
- the RDMA setup (NIC, driver and firmware, RoCEv2 or iWARP, or soft-RoCE / soft-iWARP) and the engine version, if
  relevant;
- what an attacker needs (network position, credentials, a compromised memory node or GPU host) and what they gain;
- steps to reproduce, a proof of concept if you have one, and any logs (please remove secrets and certificates).

## What to expect

miracache is a small project in alpha. We will do our best to:

- acknowledge your report within a few working days;
- keep you informed while we investigate and fix it;
- agree with you on a disclosure date, and credit you in the release notes unless you prefer otherwise.

We cannot offer a bug bounty.

## Supported versions

While miracache is in alpha, only the **latest alpha release** receives security fixes. Please check that a problem
still exists in the latest release before reporting it.

## Scope

The security model, including what miracache does **not** protect against (for example, a compromised GPU host that
holds the deployment secret, or traffic analysis by a memory node), is described in
[docs/security.md](docs/security.md). Reports that a documented residual risk exists are still welcome if you see a
practical way to reduce it.
