use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const AUDITED_COMMIT: &str = "1f822278396b8d6ba7084cab983efa8b80d680d0";
const LOCAL_SECURITY_ADAPTATIONS: &str =
    "lib/arrays/dense.h,lib/circuits/ecdsa/verify_witness.h,lib/circuits/mdoc/mdoc_zk.cc";
const AUDITED_FILES: &[(&str, &str)] = &[
    (
        "lib/arrays/dense.h",
        "8ceac07906195e6749ca15a40b814f03f7a71eb67834ae120158ed9b1fc48479",
    ),
    (
        "lib/algebra/fp24.h",
        "ea0c559299a085d9dcab3785bd80f44a37dd7965e565153bf31601317aba8a70",
    ),
    (
        "lib/algebra/fp_generic.h",
        "53a67a5d21a6f101eb92c0e14e5fab4574fc652fa17ad13614d9d9fe67314273",
    ),
    (
        "lib/zk/zk_prover.h",
        "ba1d5af734eb2d574a0b4fcc86ce6a70045a9daaa06363874c7f75e023e5495a",
    ),
    (
        "lib/circuits/ecdsa/verify_witness.h",
        "8ef0dbd017487fafa78a79cf5ac4a50f6da3be8e6be72bc77cf9bfb287bd32eb",
    ),
    (
        "lib/circuits/mdoc/mdoc_zk.cc",
        "41ef5eda0c323beb2d6d2bbcfbce9a01d422d262aca3e4d4b57816ca38795086",
    ),
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
        "f6130cf2f67a1a59b77633e2ce362344d5c8b52949b8f02c1cf5bbf9eb1f5ba0",
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
        "lib/merkle/merkle_commitment.h",
        "7e0b2ce376643a79005d7647b4c53ef26f4a3176945c0c2bc17ea12901d7c3b2",
    ),
    (
        "lib/random/random.h",
        "a01ac2541cf24222d3008d450914d3ce2f365ae785e1ef68baee4e399623ac8d",
    ),
    (
        "lib/random/transcript.h",
        "c5e1dbfd1d403aca10021591b00a60d3f18355a331464620a5af421c7e0dc1c9",
    ),
    (
        "lib/util/crypto.h",
        "309c934c9a3e09014eebfbde94b20ca9efd44568ee1a9bfab8e7c2b9f0192b5b",
    ),
    (
        "lib/util/secure_wipe.h",
        "75179bf6d7d9caa09a9106d7eabd26595e2efcd2c05d5c6cb4db0d0816c69b6b",
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
            .any(|line| line == format!("base_commit={AUDITED_COMMIT}")),
        "vendored revision must pin audited Longfellow base commit {AUDITED_COMMIT}"
    );
    assert!(
        revision
            .lines()
            .any(|line| line == "adaptation_manifest=tests/vendored_source_parity.rs"),
        "vendored local security adaptations must name their executable manifest"
    );
    assert!(
        revision.lines().any(|line| {
            line == format!("local_security_adaptations={LOCAL_SECURITY_ADAPTATIONS}")
        }),
        "vendored local security adaptations must be enumerated"
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
