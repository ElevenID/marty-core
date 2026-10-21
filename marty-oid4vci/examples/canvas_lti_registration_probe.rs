//! Read-only manual-registration diagnostics. No Canvas or ElevenID credential is used.
//! Run with an explicitly approved origin and its operator-selected trust profile.
use marty_oid4vci::lti::{
    probe_canvas_lti_registration, CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let origin = args
        .next()
        .ok_or("usage: canvas_lti_registration_probe <origin> <trust-profile>")?;
    let profile = args
        .next()
        .ok_or("an explicit operator trust profile is required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let allowlist = if profile == CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN {
        vec![origin.clone()]
    } else {
        vec![]
    };
    let probe =
        probe_canvas_lti_registration(&origin, &profile, &allowlist, 15, false, false).await?;
    println!(
        "{}",
        serde_json::json!({
            "scope": "READ_ONLY_CANVAS_MANUAL_REGISTRATION_PROBE",
            "canvasOrigin": probe.canvas_base_url,
            "issuer": probe.issuer,
            "jwksUri": probe.jwks_uri,
            "publicKeyCount": probe.jwks_json["keys"].as_array().map_or(0, Vec::len),
            "metadataSource": probe.raw_openid_configuration["elevenid_metadata_source"],
            "discoveryDocumentObserved": probe.raw_openid_configuration["discovery_document_observed"],
            "productionDemoQualified": false,
        })
    );
    Ok(())
}
