use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const AUDITED_COMMIT: &str = "f19b357440ceb704c521678cf7bbe144eeab5f49";
const AUDITED_FILES: &[(&str, &str)] = &[
    (
        "lib/circuits/mac/mac_witness.h",
        "1a9a680d5b967649b3a66d47c3cede3d69f6d903a36575100eb7ae072fb8029f",
    ),
    (
        "lib/circuits/mdoc/mdoc_signature_test.cc",
        "0f2b062653af853e2b463b504a5283008cf079372448fbfdec35cda1bc6c231c",
    ),
    (
        "lib/circuits/mdoc/mdoc_witness.h",
        "02cde8facc5c8cca52233f65d2d6a3a3cffe5cd8ca7ae1c2eb1e44cd4615254b",
    ),
    (
        "lib/ligero/ligero_param.h",
        "912dcdc250b6e2eb7cf97c23a5183946b17bed26d926aea1bdd5ee07daecca64",
    ),
    (
        "lib/ligero/ligero_prover.h",
        "876f00add75c5d094ddd45a7bd4b430157deb163bcc35ab4de72977efc2659d9",
    ),
    (
        "lib/ligero/ligero_test.cc",
        "5189285938126a4f84d0fd1d0c3bab6528932175f994ce4a920be7c480129df3",
    ),
    (
        "lib/util/secure_wipe.h",
        "ca149f38fde361593d50647d2a663b736a4329ef6612cb8009cd1d3f7a9c6cb3",
    ),
];

fn canonical_sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let source = String::from_utf8(bytes)
        .unwrap_or_else(|error| panic!("{} is not UTF-8: {error}", path.display()))
        .replace("\r\n", "\n");
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

#[test]
fn vendored_longfellow_matches_audited_security_sources() {
    let vendor = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/longfellow-zk");
    let revision = fs::read_to_string(vendor.join("VENDORED_REVISION"))
        .expect("read vendored Longfellow revision");
    assert!(
        revision
            .lines()
            .any(|line| line == format!("commit={AUDITED_COMMIT}")),
        "vendored revision must pin audited Longfellow commit {AUDITED_COMMIT}"
    );

    for (relative, expected) in AUDITED_FILES {
        let path = vendor.join(relative);
        assert_eq!(
            canonical_sha256(&path),
            *expected,
            "vendored audited source diverged: {relative}"
        );
    }
}
