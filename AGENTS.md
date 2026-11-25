# commons-node-client — working notes for agents

`auth-wire` and `commons-node-client` live here so the node, its sidecar, the
App and `cmns` can share one wire layer without any of them depending on the
node's source.

## Rules

- **No dependency on `commons-node`.** These crates are the interface the
  node's server implements; they must not import it, and consumers must not
  import it to use them.
- **The wire is versioned, not negotiated.** A change to `control/1` or
  `auth_wire v2` is a protocol change: land it with the node's server change
  in the same release round, and bump the consumers' pin in that review.
- **The transport pins are canonical here.** `transport-pins.toml` and the
  `[patch.crates-io]` block in the root `Cargo.toml` must agree, and any
  change is a change to every consumer's graph. Run
  `python3 scripts/check-transport-pins.py Cargo.lock` after any dependency
  change; consumers run the same check against their own lockfiles.

## Provenance

Moved from `commons-node` at `7b4694e` (workspace 0.9.47; content of the
0.9.48 release commit `a142270`). Until the node switches to
pinning this repository, the node's copy is the one it builds; that switch is
its own task, in its own repository, on an isolated branch.

## Gates before a head is reported

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 scripts/check-transport-pins.py Cargo.lock
```

Some `auth-wire` tests are golden and interop tests; the interop test requires
`python3` and fails loudly without it, rather than skipping.
