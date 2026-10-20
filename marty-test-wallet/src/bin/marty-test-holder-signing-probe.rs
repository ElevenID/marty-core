//! Run only alongside the existing scoped signer agent; no HTTP endpoint is opened.
use marty_test_wallet::holder_signing_probe::probe_holder_signing;
use marty_test_wallet::signer_ipc::SignerAuthenticationKey;
use zeroize::Zeroizing;

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("Holder signing preflight accepts no arguments".into());
    }
    let endpoint = std::env::var("MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT")?;
    let key_id = std::env::var("MARTY_TEST_WALLET_HOLDER_KID")?;
    let public_jwk = std::env::var("MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK")?;
    let encoded_authentication_key = Zeroizing::new(std::env::var(
        "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY",
    )?);
    let key = SignerAuthenticationKey::from_base64url(&encoded_authentication_key)?;
    let receipt = probe_holder_signing(&endpoint, &key, &key_id, &public_jwk).await?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // No raw environment, remote response, public document or credential in errors.
        eprintln!("Holder signing preflight failed");
        std::process::exit(1);
    }
}
