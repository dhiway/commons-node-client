# commons-node-client

The Commons node's shared wire layer, in two crates:

- **`auth-wire`** — the transport-neutral, signed request, response, session
  and stream contract (auth_wire v2).
- **`commons-node-client`** — the `control/1` wire types and the client for
  them, which the node, its sidecar, the App and `cmns` share so none of them
  mirrors the wire.

The client binds no endpoint of its own: every call takes the endpoint, or a
connection on it, that the caller built. That is deliberate — the caller
chooses the network and keeps custody of its keys.

## The Commons network profile (feature `commons-profile`)

A Commons program does not choose its own network. With `commons-profile`
turned on, `profile::builder()` returns an endpoint builder that already
carries the Commons profile: the relay map, its allowlist, the DNS resolver and
the signed lookups, at the version of commons-services the node pins. The
caller adds its secret key and any bind options and binds.

```toml
commons-node-client = { git = "https://github.com/dhiway/commons-node-client", rev = "…", features = ["commons-profile"] }
```

The feature is off by default because the profile is compiled from the
Services crate's `native-client` set, which brings the chain-facing stack
(statement, broker, signing, coordination). A program that talks to the
Commons network turns it on instead of assembling relays of its own, which
spec node-access 8.1 forbids.

These crates were moved here from `commons-node` at revision `7b4694e`
(workspace version 0.9.47; the content is that of the 0.9.48 release commit
`a142270`, which changed neither crate). From here they version on their own;
consumers pin this repository by revision.

## Consumers

| Consumer | How it uses the client |
|---|---|
| `commons-node` (node, sidecar, `cmn`) | control/1 operations over iroh and the local admin socket |
| `commons-app` | the same operations from the App |
| `commons-cli` (`cmns`) | read and admin operations against a node named by a ticket |

The protocol is defined and served by the node. The client follows it, which
is why this repository's releases are cut with the node's protocol changes and
pinned by consumers rather than depended on by path.

## The transport graph

`origin-protocol` and these crates build against Dhiway's iroh and noq forks.
Cargo applies `[patch.crates-io]` only at the root of a workspace, so every
consumer repeats the block. `transport-pins.toml` is the canonical record, and
`scripts/check-transport-pins.py <Cargo.lock>` fails a consumer whose resolved
graph has drifted:

```sh
python3 scripts/check-transport-pins.py ../commons-node/Cargo.lock
```

Deliberately offline: it reads the lockfile Cargo produced, not the network.

`iroh-gossip` (the `dhiway` fork) is not in this table: it reaches consumers
through `origin-protocol`'s own pin, so it is consistent as long as every
consumer shares the same `origin-protocol` revision. It is checked there, not
here.

## Building

```sh
cargo build
cargo test
```

Toolchain pinned in `rust-toolchain.toml` (1.99.0).

## Known gaps, from the first out-of-tree caller (2026-11-25)

A program outside the node reached a live node through this client using only
a ticket and its own key (M1 of the `cmns` plan). What it had to supply
itself, and should probably live here next:

1. **Ticket parsing.** The client neither parses nor re-exports a ticket; the
   caller adds `iroh-tickets` and calls `EndpointTicket::from_str(...)`.
2. **One printed form for endpoint ids.** iroh prints hex; the node prints
   z-base-32 everywhere. The z-base-32 helper is internal to `wire.rs`.
3. **A key file format.** None exists; a caller invents one.

The profile builder was the second gap on this list; `commons-profile`
closes it (T320.30).

Enrolling a key as an admin is not on this list and never will be: only the
node's operator, on the node's machine, can make a key an admin
(`cmn admins add`). A CLI cannot bootstrap its own admin access, by design.

## Licence

Apache-2.0. See `LICENSE`.
