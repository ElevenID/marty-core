//! Actual binaries and marked disposable TLS KMS only; never beta/demo proof.
use std::{
    io::Read,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_crypto_test_support::openbao_transit::DisposableOpenBao;
use serde_json::Value;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Endpoint {
    name: String,
    #[cfg(unix)]
    directory: std::path::PathBuf,
}
impl Endpoint {
    fn new() -> Self {
        #[cfg(windows)]
        {
            Self {
                name: format!(
                    r"\\.\pipe\marty-test-wallet-binary-{}",
                    uuid::Uuid::new_v4()
                ),
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let directory =
                std::path::Path::new("/tmp").join(format!("mp-{}", uuid::Uuid::new_v4().simple()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            Self {
                name: directory.join("signer.sock").to_str().unwrap().to_owned(),
                directory,
            }
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // Exact owned leaf paths only; never recursive cleanup.
            let _ = std::fs::remove_file(&self.name);
            std::fs::remove_dir(&self.directory).unwrap();
        }
    }
}

fn clean_command(binary: &str, endpoint: &Endpoint, authentication: &str) -> Command {
    let mut command = Command::new(binary);
    command.env_clear();
    for name in ["PATH", "SystemRoot", "TEMP", "TMP", "HOME"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT", &endpoint.name)
        .env(
            "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY",
            authentication,
        );
    command
}

fn output_bounded(mut command: Command) -> Output {
    let mut owned = OwnedChild(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = owned.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "owned probe exceeded its execution deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    owned
        .0
        .stdout
        .take()
        .unwrap()
        .take(65537)
        .read_to_end(&mut stdout)
        .unwrap();
    owned
        .0
        .stderr
        .take()
        .unwrap()
        .take(65537)
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
    Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
#[ignore = "requires marked disposable TLS OpenBao and real compiled signer/probe binaries"]
fn actual_agent_and_probe_bind_fresh_remote_signatures_and_reject_confusion() {
    let kms = DisposableOpenBao::from_marked_env();
    let signer = kms.create_es256();
    let wrong_public = kms.create_es256();
    let endpoint = Endpoint::new();
    let mut authentication = [0u8; 32];
    SystemRandom::new().fill(&mut authentication).unwrap();
    let authentication = URL_SAFE_NO_PAD.encode(authentication);
    let key_id = signer.key_id("did:example:disposable-binary-holder");
    let mut agent = clean_command(
        env!("CARGO_BIN_EXE_marty-test-signer-agent"),
        &endpoint,
        &authentication,
    );
    signer.configure_signer_agent(&mut agent, &key_id);
    agent.env(
        "MARTY_TEST_SIGNER_AGENT_KMS_CA_CERT_PEM",
        std::env::var_os("MARTY_TEST_OPENBAO_CA_CERT").unwrap(),
    );
    let mut agent = OwnedChild(
        agent
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let probe = |public: &str, auth: &str, kid: &str| {
        let mut command = clean_command(
            env!("CARGO_BIN_EXE_marty-test-holder-signing-probe"),
            &endpoint,
            auth,
        );
        command
            .env("MARTY_TEST_WALLET_HOLDER_KID", kid)
            .env("MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK", public);
        // env_clear above deliberately excludes fixture root, nonce, and KMS token.
        output_bounded(command)
    };
    let first = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                agent.0.try_wait().unwrap().is_none(),
                "owned signer agent exited"
            );
            let result = probe(signer.public_jwk(), &authentication, &key_id);
            if result.status.success() {
                break result;
            }
            assert!(
                Instant::now() < deadline,
                "real signer/probe did not become ready"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    assert!(first.stderr.is_empty());
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let second_output = probe(signer.public_jwk(), &authentication, &key_id);
    assert!(second_output.status.success());
    assert!(second_output.stderr.is_empty());
    let second: Value = serde_json::from_slice(&second_output.stdout).unwrap();
    for receipt in [&first, &second] {
        assert_eq!(receipt["scope"], "HOLDER_SIGNING_PREFLIGHT_ONLY");
        assert_eq!(receipt["productionDemoReady"], false);
        assert_eq!(receipt["verified"], true);
        assert_eq!(receipt["holderKeyId"], key_id);
        let signature = URL_SAFE_NO_PAD
            .decode(receipt["signatureBase64url"].as_str().unwrap())
            .unwrap();
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                receipt["challenge"].as_str().unwrap().as_bytes(),
                &signature,
                signer.public_jwk(),
                "ES256",
            )
            .unwrap()
        );
    }
    assert_ne!(first["challenge"], second["challenge"]);
    for result in [
        probe(wrong_public.public_jwk(), &authentication, &key_id),
        probe(
            signer.public_jwk(),
            &URL_SAFE_NO_PAD.encode([0xa5; 32]),
            &key_id,
        ),
        probe(signer.public_jwk(), &authentication, "unapproved-holder"),
    ] {
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"Holder signing preflight failed\n");
    }
    let recovery_output = probe(signer.public_jwk(), &authentication, &key_id);
    assert!(recovery_output.status.success());
    assert!(recovery_output.stderr.is_empty());
    let recovery: Value = serde_json::from_slice(&recovery_output.stdout).unwrap();
    assert_eq!(recovery["verified"], true);
    assert_ne!(recovery["challenge"], first["challenge"]);
    assert_ne!(recovery["challenge"], second["challenge"]);
    // Reap actual owned agent before endpoint cleanup, including on panic.
    drop(agent);
}
