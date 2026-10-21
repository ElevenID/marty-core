use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const AUDITED_COMMIT: &str = "c4004b5edee8cbc4e2a76588c531f07994e3e7ab";
const LOCAL_SECURITY_ADAPTATIONS: &str =
    "lib/arrays/dense.h,lib/circuits/mdoc/mdoc_zk.cc,lib/gf2k/gf2_128.h";
const AUDITED_FILES: &[(&str, &str)] = &[
    (
        "lib/algebra/nat.cc",
        "c4090a5ee793764a2b04b39e48ad5819c3111e6acfb303e826a93a7d4b07442c",
    ),
    (
        "lib/algebra/nat.h",
        "b786c0823d014f7dca8b2c55347cb7e4cc636da2ddb20f2d5f6d7a7068e39558",
    ),
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
        "lib/gf2k/gf2_128.h",
        "66d49fec40b8c11e085ecf5fc9d1dd5979c52a663e8213b9e815f424aedb0433",
    ),
    (
        "lib/zk/zk_prover.h",
        "ba1d5af734eb2d574a0b4fcc86ce6a70045a9daaa06363874c7f75e023e5495a",
    ),
    (
        "lib/cbor/host_decoder.h",
        "f5340fd6f45f424f20d36b46ed8f96f9c55bed45f853a5dd30e2a8f71ff1e410",
    ),
    (
        "lib/cbor/host_decoder_test.cc",
        "2fdaebcf4a7e982a228059052ade4e7f5136554c9f9d6eb76cb8ce1b685a6b33",
    ),
    (
        "lib/circuits/ecdsa/verify_witness.h",
        "8ef0dbd017487fafa78a79cf5ac4a50f6da3be8e6be72bc77cf9bfb287bd32eb",
    ),
    (
        "lib/circuits/cbor_parser/cbor.h",
        "bb717089d731912fb8e1ed5be1d4a13235d59b22134ee80744940750ca4978b3",
    ),
    (
        "lib/circuits/cbor_parser/cbor_test.cc",
        "0f6816e51850e5655b71e4cc68a53f90b05ef34c9ba6793411dc524a56b08de3",
    ),
    (
        "lib/circuits/cbor_parser/cbor_testing.h",
        "640f8e365bef79a3eb066f9559f370c03e436ee9dbef54f5f96a82362b76cc80",
    ),
    (
        "lib/circuits/cbor_parser/cbor_witness.h",
        "7e1b564231804ac66d07e137bd6f50340fc7524da5cd9ad0e74e483ced32df1f",
    ),
    (
        "lib/circuits/cbor_parser/mso2_test.cc",
        "7643fb00dd76321c6cadc3dd6c17ed60274326d1e610cc265f1fd3636c9a2897",
    ),
    (
        "lib/circuits/mdoc/CMakeLists.txt",
        "437399f2ea67a842ceff23a433c80259ddbc69fffa7543526ba12ab628cee93c",
    ),
    (
        "lib/circuits/mdoc/mdoc_examples.h",
        "59d9c46ba7048c22e4d4782e8adab6fb491a2bf5550f1f5e44c67cfbe391bee2",
    ),
    (
        "lib/circuits/mdoc/mdoc_parser_test.cc",
        "fa74c371ac7ec0e8e04b849d5fd1f0034e710da81f7d5643e7f59550779135b7",
    ),
    (
        "lib/circuits/mdoc/mdoc_zk.cc",
        "65e86ede7801d4577d1fa445a39c050657e45b6bd172fa0af6b06a3073cf0333",
    ),
    (
        "lib/circuits/mdoc/mdoc_zk_test.cc",
        "1d0066dc1ccf2577ad317a43648c41c5dd97984c14f9e937412f5aeeee9356b4",
    ),
    (
        "lib/circuits/mac/mac_witness.h",
        "1a9a680d5b967649b3a66d47c3cede3d69f6d903a36575100eb7ae072fb8029f",
    ),
    (
        "lib/circuits/mdoc/mdoc_signature_test.cc",
        "eb5eba3e670fa426082f1f4cbfedae7ba7f253ff3c568fb37b5b967b6b1aadba",
    ),
    (
        "lib/circuits/mdoc/mdoc_witness.h",
        "1a6cc5457d4f85acf316bd25562a153be29f8db29efa22ad2dd887fd8241bc21",
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
        "010deec68fe62cb9399a1ca7b4ca5376dd67ffa01f8a48a1d1ed4e0c8124509f",
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
        "e338ce7dea04586d3ab83e644961609470a2ee15efe402861dee310a1532a0bb",
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
    let build_script = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
        .expect("read marty-zkp build script");
    assert!(
        build_script.contains("println!(\"cargo:rerun-if-changed={}\", lib_src.display());"),
        "native build must rerun whenever vendored Longfellow sources change"
    );

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
