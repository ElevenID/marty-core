//! DIDComm v2 envelope packing for credential delivery.
//!
//! Packs a signed credential (SD-JWT, mDoc, etc.) into a DIDComm v2
//! plaintext message with the credential as an attachment.
//!
//! The message type follows the Aries Issue Credential v3 protocol:
//! `https://didcomm.org/issue-credential/3.0/issue-credential`

use crate::error::{DidcommError, DidcommResult};
use crate::types::{Attachment, AttachmentData, DidcommMessage};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// PIURI for DIDComm credential issuance message
const ISSUE_CREDENTIAL_TYPE: &str = "https://didcomm.org/issue-credential/3.0/issue-credential";

/// Pack a signed credential into a DIDComm v2 plaintext message.
///
/// This creates the plaintext envelope. The caller is responsible for
/// encrypting (authcrypt/anoncrypt) and delivering to the holder's
/// DIDComm service endpoint.
///
/// # Arguments
///
/// * `credential` — The signed credential string (SD-JWT, JWT, or base64-encoded mDoc)
/// * `format` — Credential format MIME type (e.g. `"vc+sd-jwt"`, `"mso_mdoc"`, `"jwt_vc_json"`)
/// * `issuer_did` — The issuer's DID
/// * `holder_did` — The holder/recipient DID
/// * `thread_id` — Optional thread ID for correlation with a prior offer
/// * `credential_id` — Optional credential identifier
pub fn pack_credential_for_holder(
    credential: &str,
    format: &str,
    issuer_did: &str,
    holder_did: &str,
    thread_id: Option<&str>,
    credential_id: Option<&str>,
) -> DidcommResult<String> {
    let msg_id = uuid::Uuid::new_v4().to_string();
    let attachment_id = credential_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let media_type = format_to_media_type(format);

    let created_time = chrono::Utc::now().timestamp() as u64;

    let message = DidcommMessage {
        id: msg_id,
        r#type: ISSUE_CREDENTIAL_TYPE.to_string(),
        from: Some(issuer_did.to_string()),
        to: Some(vec![holder_did.to_string()]),
        created_time: Some(created_time),
        expires_time: None,
        body: serde_json::json!({
            "goal_code": "issue-vc",
            "comment": "Here is your credential"
        }),
        attachments: vec![Attachment {
            id: Some(attachment_id),
            media_type: Some(media_type.to_string()),
            format: Some(format.to_string()),
            data: AttachmentData {
                base64: Some(URL_SAFE_NO_PAD.encode(credential.as_bytes())),
                json: None,
                links: None,
            },
        }],
        thid: thread_id.map(|s| s.to_string()),
        pthid: None,
    };

    serde_json::to_string(&message).map_err(|e| DidcommError::PackError(e.to_string()))
}

/// Unpack a DIDComm plaintext message (JSON string) into a `DidcommMessage`.
pub fn unpack_didcomm_message(json: &str) -> DidcommResult<DidcommMessage> {
    serde_json::from_str(json).map_err(|e| DidcommError::UnpackError(e.to_string()))
}

/// Map credential format to IANA media type.
fn format_to_media_type(format: &str) -> &str {
    match format {
        "vc+sd-jwt" | "dc+sd-jwt" | "w3c_vcdm_v2_sd_jwt" | "ietf_sd_jwt" => "application/vc+sd-jwt",
        "mso_mdoc" | "mdoc" => "application/cbor",
        "jwt_vc_json" | "jwt_vc" => "application/jwt",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_credential() {
        let result = pack_credential_for_holder(
            "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoYVhnQloifQ.sig",
            "vc+sd-jwt",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            Some("thread-123"),
            Some("cred-001"),
        )
        .unwrap();

        let msg: DidcommMessage = serde_json::from_str(&result).unwrap();
        assert_eq!(msg.r#type, ISSUE_CREDENTIAL_TYPE);
        assert_eq!(
            msg.from.as_deref(),
            Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        );
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(
            msg.attachments[0].media_type.as_deref(),
            Some("application/vc+sd-jwt")
        );
        assert_eq!(msg.thid.as_deref(), Some("thread-123"));
    }

    #[test]
    fn test_unpack_roundtrip() {
        let packed = pack_credential_for_holder(
            "test-credential",
            "jwt_vc_json",
            "did:key:issuer",
            "did:key:holder",
            None,
            None,
        )
        .unwrap();

        let msg = unpack_didcomm_message(&packed).unwrap();
        assert_eq!(msg.from.as_deref(), Some("did:key:issuer"));

        // Decode the attachment
        let att = &msg.attachments[0];
        let decoded = URL_SAFE_NO_PAD
            .decode(att.data.base64.as_ref().unwrap())
            .unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), "test-credential");
    }
}
