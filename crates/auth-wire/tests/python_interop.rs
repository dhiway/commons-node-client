#[test]
fn dependency_free_python_verifies_all_v2_signatures() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/verify_auth_wire.py"
        ))
        .status()
        .expect("python3 is required by the repository validation environment");
    assert!(status.success());
}
