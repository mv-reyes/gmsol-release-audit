# gmsol-release-audit

Read-only integrity auditor for the GMTrade (gmsol) deployment.

Written while reviewing the protocol for the bug-bounty program — the first
integration step (installing the SDK) surfaced a broken release artifact, and
it snowballed into a general health check. Everything here is read-only:
public registry metadata, the verified-build registry, and public RPC reads.
No transactions are constructed or sent.

## What it checks

1. **Release artifacts** — npm tarball completeness against declared files,
   crates.io version parity for the `gmsol-*` family.
2. **Deployment provenance** — verified-build status of the five deployed
   programs against the public registry.
3. **Authority hygiene** — Store role-holders cross-referenced with their
   on-chain activity, flagging dormant keys that still hold live roles.
4. **Governance config** — multisig threshold, timelock, and the live quorum
   margin (active vs dormant signers).

## Usage

```
cargo run
```

One pass, prints a report. No arguments, no writes.

## Findings context

See the linked issue for what prompted this. The short version: release
artifacts and authority custody drift silently; the only way to notice is to
look, and looking should be one command.
