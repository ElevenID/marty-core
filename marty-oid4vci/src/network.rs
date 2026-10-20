//! Shared network address classification and pinned public wallet fetches.

use std::net::IpAddr;
#[cfg(feature = "wallet")]
use std::net::SocketAddr;

pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [first, second, third, _] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                || first == 0
                || first >= 240
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 198 && (18..=19).contains(&second))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_private_ip(IpAddr::V4(mapped)))
        }
    }
}

#[cfg(feature = "wallet")]
fn require_public_addresses(addresses: &[SocketAddr]) -> crate::Oid4vciResult<()> {
    if addresses.is_empty() || addresses.iter().any(|address| {
        let ip = address.ip();
        is_private_ip(ip) || matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xe000) != 0x2000 || v6.segments()[0] == 0x2002)
    }) {
        return Err(crate::Oid4vciError::InvalidRequest("Wallet request objects require public network addresses".into()));
    }
    Ok(())
}

#[cfg(feature = "wallet")]
pub(crate) async fn public_request_client(
    uri: &str,
) -> crate::Oid4vciResult<(reqwest::Client, url::Url)> {
    let invalid = || {
        crate::Oid4vciError::InvalidRequest(
            "Wallet request objects require a public HTTPS URL without credentials or fragments"
                .into(),
        )
    };
    let url = url::Url::parse(uri).map_err(|_| invalid())?;
    let host = url.host().ok_or_else(invalid)?.to_string();
    let test_loopback = cfg!(test)
        && url.scheme() == "http"
        && matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
    if (url.scheme() != "https" && !test_loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let port = url.port_or_known_default().ok_or_else(invalid)?;
    let dns_host = host.trim_start_matches('[').trim_end_matches(']');
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((dns_host, port)),
    )
    .await
    .map_err(|_| invalid())?
    .map_err(|_| invalid())?
    .collect::<Vec<_>>();
    if !test_loopback {
        require_public_addresses(&addresses)?;
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .resolve_to_addrs(dns_host, &addresses)
        .user_agent("marty-wallet/0.1")
        .build()
        .map_err(|_| invalid())?;
    Ok((client, url))
}

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;

    #[test]
    fn request_dns_rejects_mixed_empty_and_nonpublic_answers() {
        let socket = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 443);
        assert!(require_public_addresses(&[]).is_err());
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
        ] {
            assert!(
                require_public_addresses(&[socket("8.8.8.8"), socket(private)]).is_err(),
                "{private}"
            );
        }
        assert!(
            require_public_addresses(&[socket("8.8.8.8"), socket("2606:4700:4700::1111")]).is_ok()
        );
    }

    #[tokio::test]
    async fn request_fetch_refuses_unsafe_urls_before_connecting() {
        for uri in [
            "http://169.254.169.254/metadata",
            "file:///etc/passwd",
            "https://user:secret@example.com/request",
            "https://example.com/request#fragment",
            "https://127.0.0.1/request",
            "https://[::ffff:127.0.0.1]/request",
        ] {
            assert!(public_request_client(uri).await.is_err(), "{uri}");
        }
    }
}
