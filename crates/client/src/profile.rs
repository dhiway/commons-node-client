//! The Commons network profile (spec node-access 8.1): the one way a Commons
//! program builds its endpoint.
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

pub use endpoint::profile::{Error, NamedProfile, NetworkDescriptor};
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
/// and any bind options, then binds. A caller that already configured a
/// builder of its own (an accept-only ALPN, say) uses this rather than
/// [`builder`], so nothing it sets before this call is lost.
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

    /// The whole point of the export: the relay set a consumer gets is the
    /// Commons pair, not whatever its ticket or its argument named.
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

    /// Both entry points return a builder rather than an error, and a caller's
    /// own configuration can be added on top without losing the profile.
    #[test]
    fn the_builder_carries_the_profile_for_the_caller() {
        let key = iroh::SecretKey::from_bytes(&[7; 32]);
        let _ = builder()
            .expect("the profile configures a builder")
            .secret_key(key.clone())
            .alpns(vec![b"commons-node/control/1".to_vec()]);
        let _ = configure(iroh::Endpoint::builder(iroh::endpoint::presets::Minimal))
            .expect("the profile configures a caller's builder");
    }
}
