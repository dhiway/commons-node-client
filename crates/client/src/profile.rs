//! The Commons network profile (spec node-access 1.7 and 8.1): the one way a
//! Commons program builds its endpoint.
//!
//! A Commons program does not choose its own network. The relays, their
//! allowlist, the DNS resolver and the signed lookups all come from the
//! profile commons-services compiles in, which is the same composition the node
//! uses; the caller adds its identity and its bind options and nothing else. It
//! never names a relay of its own, and it never falls back to n0's default
//! relays or lookup (architecture principle 1, ruling 93).
//!
//! The profile `cmns-staging` names no runtime version: compatibility with the
//! chain's live metadata is checked at the chain, not read from here
//! (ruling 117). The Services revision this module compiles is the one the node
//! pins, so a consumer and the node it talks to select the same network.

use endpoint::profile::NamedProfile;
pub use endpoint::profile::{Error, NetworkDescriptor};
use iroh::endpoint::Builder;

/// The named profile every Commons program builds from.
pub const PROFILE: &str = "cmns-staging";

/// The Commons profile as a descriptor, for a caller that needs to read its
/// relays, providers or genesis rather than configure a builder with it.
pub fn descriptor() -> Result<NetworkDescriptor, Error> {
    NamedProfile::parse(PROFILE)?.descriptor()
}

/// `builder` with the Commons profile applied: its preset, relay map, relay
/// allowlist, DNS resolver and signed lookups. The caller sets its secret key
/// and any bind options, then binds.
///
/// What a caller set before this call: its identity, its ALPNs, its IP binds
/// and its transport configuration are kept; any address lookup, relay or DNS
/// resolver it set is **replaced** by the profile's. That replacement is the
/// safety property, not a side effect — it is what removes N0's relays and
/// lookup from a builder that had them.
pub fn configure(builder: Builder) -> Result<Builder, Error> {
    descriptor()?.configure_endpoint(builder)
}

/// A fresh endpoint builder carrying the Commons profile, ready for the
/// caller's secret key and bind options.
pub fn builder() -> Result<Builder, Error> {
    configure(iroh::Endpoint::builder(iroh::endpoint::presets::Minimal))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay set a consumer reads is the Commons pair.
    #[test]
    fn the_relay_set_is_the_commons_pair() {
        let descriptor = descriptor().expect("the compiled profile parses");
        assert_eq!(descriptor.id(), PROFILE);
        let relays: Vec<String> = descriptor.relays().map(ToString::to_string).collect();
        assert_eq!(
            relays,
            [
                "https://relay.fra.staging.cmns.tech/",
                "https://relay.bom.staging.cmns.tech/"
            ]
        );
    }

    /// The builder this module hands out carries the profile's allowlist: bind
    /// refuses a relay outside the Commons pair before any network effect, so a
    /// `configure` that applied nothing would fail here. Checked through both
    /// entry points.
    #[tokio::test]
    async fn bind_refuses_a_relay_outside_the_commons_pair() {
        let foreign: iroh::RelayUrl = "http://127.0.0.1:9/".parse().unwrap();
        for builder in [
            builder().expect("the profile configures a builder"),
            configure(iroh::Endpoint::builder(iroh::endpoint::presets::Minimal))
                .expect("the profile configures a caller's builder"),
        ] {
            let result = builder
                .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
                    foreign.clone(),
                ])))
                .clear_address_lookup()
                .clear_ip_transports()
                .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("a loopback bind address")
                .bind()
                .await;
            assert!(
                result.is_err(),
                "a relay outside the Commons pair was accepted"
            );
        }
    }

    /// The profile reaches the builder, and a caller's key and ALPNs sit on top
    /// of it.
    #[test]
    fn the_builder_carries_the_profile_for_the_caller() {
        let key = iroh::SecretKey::from_bytes(&[7; 32]);
        let _ = builder()
            .expect("the profile configures a builder")
            .secret_key(key.clone())
            .alpns(vec![b"commons-node/control/1".to_vec()]);
    }
}
