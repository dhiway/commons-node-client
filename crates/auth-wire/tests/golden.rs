use auth_wire::SignedWire;

/// The v2 fixture is the producer's own golden envelopes, frozen: each
/// decodes canonically, verifies, and still equals what the producer builds,
/// so a change to the v2 wire shows up here.
#[test]
fn external_v2_vectors_are_canonical_verified_and_match_the_producer() {
    use auth_wire::v2::{
        SessionCertificate, SignedRequest, SignedResponse, SignedStreamFrame, golden,
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/auth_wire_v2.json")).unwrap();
    let bytes = |name: &str| hex::decode(fixture[name].as_str().unwrap()).unwrap();
    let key = iroh::SecretKey::from_bytes(&golden::ISSUER).public();

    let request = SignedRequest::decode(&bytes("request")).unwrap();
    request.verify_proofs().unwrap();
    assert_eq!(request, golden::request());
    let response = SignedResponse::decode(&bytes("response")).unwrap();
    auth_wire::verify(&response, key.as_bytes()).unwrap();
    assert_eq!(response, golden::response());
    let session = SessionCertificate::decode(&bytes("session")).unwrap();
    auth_wire::verify(&session, key.as_bytes()).unwrap();
    assert_eq!(session, golden::session());
    let stream = SignedStreamFrame::decode(&bytes("stream")).unwrap();
    auth_wire::verify(&stream, key.as_bytes()).unwrap();
    assert_eq!(stream, golden::stream());
}
