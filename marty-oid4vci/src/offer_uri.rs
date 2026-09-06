//! Pure credential-offer URI formatting shared by engine and language bindings.

/// Preserve the established URI wire format, including unknown-scheme fallback.
pub fn generate_offer_uri(issuer_url: &str, offer_id: &str, format: &str) -> String {
    match format {
        "microsoft" => format!(
            "openid-vc://?request_uri={}/issuance-requests/{}",
            issuer_url, offer_id
        ),
        _ => format!(
            "openid-credential-offer://?credential_offer_uri={}/offers/{}",
            issuer_url, offer_id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_wire_formats_and_unescaped_identifiers() {
        for format in ["oid4vci", "", "unknown", "microsoft"] {
            let expected = if format == "microsoft" {
                "openid-vc://?request_uri=https://issuer.example/base//issuance-requests/a/b?x=1&y=2"
            } else {
                "openid-credential-offer://?credential_offer_uri=https://issuer.example/base//offers/a/b?x=1&y=2"
            };
            assert_eq!(
                generate_offer_uri("https://issuer.example/base/", "a/b?x=1&y=2", format),
                expected
            );
        }
    }
}
