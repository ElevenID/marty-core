//! Bounded CWT evaluation for an opaque authenticated MSO reference.
//! Fetch permission belongs to the caller's governed transport, not this module.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use ciborium::Value;
use coset::{iana, CoseSign1, RegisteredLabelWithPrivate};
use der::{Decode, Encode};
use flate2::{Decompress, FlushDecompress, Status};
use isomdl::{
    cose::{
        sign1::{P256Verifier, P384Verifier},
        MaybeTagged,
    },
    definitions::x509::{
        revocation::{CrlError, RevocationFetcher},
        trust_anchor::{TrustAnchor, TrustAnchorRegistry},
        validation::{
            validate_with_options, CertificateProfile, StatusListSignerProfile, ValidationOptions,
        },
        SupportedCurve, X5Chain,
    },
};
use time::OffsetDateTime;
use x509_cert::{crl::CertificateList, Certificate};

use super::{AuthenticatedMdocStatusRequest, MdocStatusReference};

const MAX_TOKEN: usize = 2 * 1024 * 1024;
const MAX_LIST: usize = 1024 * 1024;
const MAX_AGE: i64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdocExternalStatus {
    Valid,
    Revoked,
}

/// Authenticated status result, with no serde construction path.
#[derive(Debug)]
pub struct VerifiedMdocExternalStatus {
    status: MdocExternalStatus,
    source_binding: [u8; 32],
    checked_at: OffsetDateTime,
    valid_until: OffsetDateTime,
}

impl VerifiedMdocExternalStatus {
    #[must_use]
    pub fn status_for(
        &self,
        request: &AuthenticatedMdocStatusRequest,
    ) -> Result<MdocExternalStatus, String> {
        if self.source_binding != request.source_binding_digest() {
            return Err("status observation belongs to another authenticated source".into());
        }
        Ok(self.status)
    }
    #[must_use]
    pub fn checked_at(&self) -> OffsetDateTime {
        self.checked_at
    }
    #[must_use]
    pub fn valid_until(&self) -> OffsetDateTime {
        self.valid_until
    }
}

/// Verify bytes fetched for this exact authenticated reference. The caller must
/// supply a bounded, destination-governed CRL fetcher and current owner approval.
/// Yielding asynchronous work, including CRL awaits, has a fifteen-second
/// deadline. Synchronous work is structurally bounded, not preempted by Tokio.
/// All failures mean unavailable/unverified status, never an invented clear bit.
pub async fn verify_mdoc_external_status<R, F>(
    request: &AuthenticatedMdocStatusRequest,
    token: &[u8],
    fetcher: &R,
    clock: F,
) -> Result<VerifiedMdocExternalStatus, String>
where
    R: RevocationFetcher,
    F: Fn() -> OffsetDateTime,
{
    tokio::time::timeout(Duration::from_secs(15), async {
        let initial = clock();
        request
            .revalidate_at(initial)
            .map_err(|_| "mdoc status source is not current")?;
        let parsed = ParsedToken::parse(token, request.reference())?;
        let authority = Certificate::from_der(request.status_authority_certificate_der())
            .map_err(|_| "invalid authenticated status authority")?;
        let recording = RecordedCrls::new(fetcher);
        authenticate(&parsed, &authority, &recording, initial).await?;
        // A final pass may only replay the exact observed CRLs. It cannot do a
        // second network round trip and silently extend the observation window.
        recording.sealed.store(true, Ordering::SeqCst);
        let final_time = clock();
        if final_time < initial {
            return Err("status verifier clock moved backwards".into());
        }
        request
            .revalidate_at(final_time)
            .map_err(|_| "mdoc status source expired")?;
        authenticate(&parsed, &authority, &recording, final_time).await?;
        let mut until = parsed.valid_until(final_time)?.min(request.valid_until());
        for certificate in parsed.chain.iter() {
            until = until.min(certificate_expiry(&certificate.inner)?);
        }
        for crl in recording
            .responses
            .lock()
            .map_err(|_| "status CRL state unavailable")?
            .values()
        {
            let next = crl
                .tbs_cert_list
                .next_update
                .ok_or("status signer CRL has no expiry")?;
            let next =
                OffsetDateTime::from_unix_timestamp(next.to_unix_duration().as_secs() as i64)
                    .map_err(|_| "invalid status signer CRL expiry")?;
            until = until.min(next);
        }
        if final_time >= until {
            return Err("status authority expired during verification".into());
        }
        Ok(VerifiedMdocExternalStatus {
            status: parsed.status,
            source_binding: request.source_binding_digest(),
            checked_at: final_time,
            valid_until: until,
        })
    })
    .await
    .map_err(|_| "mdoc status verification deadline exceeded".to_owned())?
}

struct ParsedToken {
    cose: MaybeTagged<CoseSign1>,
    chain: X5Chain,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    ttl: Option<i64>,
    status: MdocExternalStatus,
}

impl ParsedToken {
    fn parse(bytes: &[u8], reference: &MdocStatusReference) -> Result<Self, String> {
        let outer = decode(bytes, MAX_TOKEN)?;
        let outer = match &outer {
            Value::Tag(18, inner) => inner.as_ref(),
            Value::Tag(_, _) => return Err("unsupported status COSE tag".into()),
            value => value,
        };
        let array = outer
            .as_array()
            .filter(|a| a.len() == 4)
            .ok_or("invalid status COSE envelope")?;
        let protected = decode(
            array[0]
                .as_bytes()
                .ok_or("missing protected status header")?,
            32768,
        )?;
        let protected = protected
            .as_map()
            .ok_or("invalid protected status header")?;
        let unprotected = array[1]
            .as_map()
            .ok_or("invalid unprotected status header")?;
        if protected
            .iter()
            .any(|(key, _)| unprotected.iter().any(|(other, _)| key == other))
            || integer_member(protected, 2).is_some()
            || integer_member(unprotected, 2).is_some()
        {
            return Err("ambiguous or critical status COSE headers".into());
        }
        let expected_type = match reference {
            MdocStatusReference::StatusList { .. } => "application/statuslist+cwt",
            MdocStatusReference::IdentifierList { .. } => "application/identifierlist+cwt",
        };
        if integer_member(protected, 16).and_then(Value::as_text) != Some(expected_type) {
            return Err("status CWT type does not match authenticated mechanism".into());
        }
        let algorithm = integer_member(protected, 1).ok_or("missing protected status algorithm")?;
        if !matches!(integer(algorithm), Ok(-7 | -35)) {
            return Err("unsupported status algorithm".into());
        }
        let signature_len = if integer(algorithm)? == -7 { 64 } else { 96 };
        if !array[3]
            .as_bytes()
            .is_some_and(|signature| signature.len() == signature_len)
        {
            return Err("invalid status signature size".into());
        }
        let chain = integer_member(protected, 33).ok_or("missing protected status signer chain")?;
        let chain_items: Vec<_> = match chain {
            Value::Bytes(cert) => vec![cert],
            Value::Array(certs) => certs
                .iter()
                .map(|cert| cert.as_bytes().ok_or("invalid status certificate"))
                .collect::<Result<_, _>>()?,
            _ => return Err("invalid status signer chain".into()),
        };
        if chain_items.is_empty()
            || chain_items.len() > 8
            || chain_items
                .iter()
                .any(|cert| cert.is_empty() || cert.len() > 65536)
        {
            return Err("status signer chain exceeds limits".into());
        }
        let payload = array[2]
            .as_bytes()
            .ok_or("detached status payload is unsupported")?;
        let claims = decode(payload, MAX_TOKEN)?;
        let claims = claims.as_map().ok_or("invalid status claims")?;
        let uri = match reference {
            MdocStatusReference::StatusList { uri, .. }
            | MdocStatusReference::IdentifierList { uri, .. } => uri,
        };
        if integer_member(claims, 2).and_then(Value::as_text) != Some(uri.as_str()) {
            return Err("status subject does not match authenticated reference".into());
        }
        let iat = integer(integer_member(claims, 6).ok_or("missing status issuance")?)?;
        let exp = integer(integer_member(claims, 4).ok_or("missing status expiry")?)?;
        let nbf = integer_member(claims, 5).map(integer).transpose()?;
        let ttl = integer_member(claims, 65534).map(integer).transpose()?;
        let status = match reference {
            MdocStatusReference::StatusList { index, .. } => {
                if integer_member(claims, 65530).is_some() {
                    return Err("mixed status mechanisms".into());
                }
                bit_status(
                    integer_member(claims, 65533).ok_or("missing status list")?,
                    *index,
                )?
            }
            MdocStatusReference::IdentifierList { identifier, .. } => {
                if integer_member(claims, 65533).is_some() {
                    return Err("mixed status mechanisms".into());
                }
                identifier_status(
                    integer_member(claims, 65530).ok_or("missing identifier list")?,
                    identifier,
                )?
            }
        };
        let cose: MaybeTagged<CoseSign1> =
            isomdl::cbor::from_slice(bytes).map_err(|_| "invalid signed status envelope")?;
        let chain = X5Chain::from_cbor(chain.clone()).map_err(|_| "invalid status X509 chain")?;
        Ok(Self {
            cose,
            chain,
            iat,
            exp,
            nbf,
            ttl,
            status,
        })
    }

    fn valid_until(&self, now: OffsetDateTime) -> Result<OffsetDateTime, String> {
        let now = now.unix_timestamp();
        let mut until = self
            .iat
            .checked_add(MAX_AGE)
            .ok_or("status time overflow")?
            .min(self.exp);
        // Critical-use refresh policy from status-list draft10 section13.6:
        // use iat+ttl rather than resetting freshness on each verification.
        if let Some(ttl) = self.ttl {
            if ttl <= 0 {
                return Err("invalid status TTL".into());
            }
            until = until.min(self.iat.checked_add(ttl).ok_or("status TTL overflow")?);
        }
        if self.iat < 0
            || self.iat > now
            || self.exp <= self.iat
            || now >= until
            || self
                .nbf
                .is_some_and(|nbf| nbf < 0 || nbf > now || nbf >= self.exp)
        {
            return Err("status token is outside its freshness window".into());
        }
        OffsetDateTime::from_unix_timestamp(until).map_err(|_| "invalid status expiry".into())
    }
}

async fn authenticate<R: RevocationFetcher>(
    parsed: &ParsedToken,
    authority: &Certificate,
    fetcher: &R,
    now: OffsetDateTime,
) -> Result<(), String> {
    parsed.valid_until(now)?;
    verify_signature(&parsed.cose, &parsed.chain)?;
    let registry = TrustAnchorRegistry {
        anchors: vec![TrustAnchor {
            certificate: authority.clone(),
            purpose: StatusListSignerProfile.trust_purpose(),
        }],
    };
    let outcome = validate_with_options(
        &StatusListSignerProfile,
        &parsed.chain,
        &registry,
        fetcher,
        &ValidationOptions {
            validation_time: Some(now),
        },
    )
    .await;
    if !outcome.errors.is_empty() || !outcome.revocation_errors.is_empty() {
        return Err("status signer authority or revocation evidence is unavailable".into());
    }
    Ok(())
}

fn verify_signature(cose: &MaybeTagged<CoseSign1>, chain: &X5Chain) -> Result<(), String> {
    let result = match (
        SupportedCurve::from_certificate(chain.end_entity_certificate()),
        &cose.protected.header.alg,
    ) {
        (
            Some(SupportedCurve::P256),
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)),
        ) => {
            let key: ecdsa::VerifyingKey<p256::NistP256> = chain
                .end_entity_public_key()
                .map_err(|_| "invalid status signer key")?;
            cose.verify::<_, ecdsa::Signature<p256::NistP256>>(&P256Verifier::from(key), None, None)
        }
        (
            Some(SupportedCurve::P384),
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384)),
        ) => {
            let key: ecdsa::VerifyingKey<p384::NistP384> = chain
                .end_entity_public_key()
                .map_err(|_| "invalid status signer key")?;
            cose.verify::<_, ecdsa::Signature<p384::NistP384>>(&P384Verifier::from(key), None, None)
        }
        _ => return Err("status algorithm does not match signer key".into()),
    };
    result
        .into_result()
        .map_err(|_| "invalid status signature".into())
}

fn decode(bytes: &[u8], limit: usize) -> Result<Value, String> {
    if bytes.len() > limit {
        return Err("status CBOR exceeds limits".into());
    }
    let mut input = Cursor::new(bytes);
    let value = ciborium::de::from_reader_with_recursion_limit(&mut input, 32)
        .map_err(|_| "malformed or deeply nested status CBOR")?;
    if input.position() != bytes.len() as u64 {
        return Err("trailing status CBOR".into());
    }
    let mut count = 0;
    inspect(&value, &mut count)?;
    Ok(value)
}

fn inspect(value: &Value, count: &mut usize) -> Result<(), String> {
    *count += 1;
    if *count > 32768 {
        return Err("too many status CBOR values".into());
    }
    match value {
        Value::Map(map) => {
            let mut keys = BTreeSet::new();
            for (key, value) in map {
                if !matches!(key, Value::Integer(_) | Value::Text(_) | Value::Bytes(_)) {
                    return Err("unsupported status map key".into());
                }
                let encoded = isomdl::cbor::to_vec(key).map_err(|_| "invalid status map key")?;
                if !keys.insert(encoded) {
                    return Err("duplicate status CBOR key".into());
                }
                inspect(value, count)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                inspect(value, count)?;
            }
        }
        Value::Tag(_, value) => inspect(value, count)?,
        _ => (),
    }
    Ok(())
}

fn integer(value: &Value) -> Result<i64, String> {
    match value {
        Value::Integer(value) => {
            i64::try_from(*value).map_err(|_| "status integer overflow".into())
        }
        _ => Err("status value is not an integer".into()),
    }
}
fn integer_member(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find_map(|(k, v)| (integer(k).ok() == Some(key)).then_some(v))
}
fn text_member<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
}

fn bit_status(value: &Value, index: u64) -> Result<MdocExternalStatus, String> {
    let map = value.as_map().ok_or("invalid status list")?;
    if map.len() != 2 || text_member(map, "bits").map(integer).transpose()? != Some(1) {
        return Err("unsupported ISO status bit format".into());
    }
    let compressed = text_member(map, "lst")
        .and_then(Value::as_bytes)
        .ok_or("missing compressed status bits")?;
    if compressed.len() > MAX_LIST || index >= (MAX_LIST as u64) * 8 {
        return Err("status list exceeds lookup bounds".into());
    }
    let mut decoder = Decompress::new(true);
    let mut list = vec![0; MAX_LIST + 1];
    let state = decoder
        .decompress(compressed, &mut list, FlushDecompress::Finish)
        .map_err(|_| "invalid compressed status bits")?;
    if state != Status::StreamEnd
        || decoder.total_out() > MAX_LIST as u64
        || decoder.total_in() != compressed.len() as u64
    {
        return Err("incomplete, oversized or trailing compressed status bits".into());
    }
    list.truncate(decoder.total_out() as usize);
    let byte = list
        .get((index / 8) as usize)
        .ok_or("status index outside list")?;
    Ok(if byte & (1 << (index % 8)) == 0 {
        MdocExternalStatus::Valid
    } else {
        MdocExternalStatus::Revoked
    })
}

fn identifier_status(value: &Value, identifier: &[u8]) -> Result<MdocExternalStatus, String> {
    let map = value.as_map().ok_or("invalid identifier list")?;
    // Aggregation and RFU semantics are not implemented. Their presence cannot
    // turn an incomplete membership observation into a clear status.
    if map.len() != 1 || identifier.is_empty() || identifier.len() > 1024 {
        return Err("unsupported identifier list structure".into());
    }
    let identifiers = text_member(map, "identifiers")
        .and_then(Value::as_map)
        .ok_or("missing identifier map")?;
    let mut listed = false;
    for (id, info) in identifiers {
        let id = id
            .as_bytes()
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or("invalid identifier")?;
        if !info.as_map().is_some_and(|map| map.is_empty()) {
            return Err("unsupported identifier information".into());
        }
        listed |= id == identifier;
    }
    Ok(if listed {
        MdocExternalStatus::Revoked
    } else {
        MdocExternalStatus::Valid
    })
}

fn certificate_expiry(cert: &Certificate) -> Result<OffsetDateTime, String> {
    OffsetDateTime::from_unix_timestamp(
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64,
    )
    .map_err(|_| "invalid status certificate expiry".into())
}

struct RecordedCrls<'a, R> {
    source: &'a R,
    responses: Mutex<BTreeMap<String, CertificateList>>,
    requests: AtomicUsize,
    sealed: AtomicBool,
}
impl<'a, R> RecordedCrls<'a, R> {
    fn new(source: &'a R) -> Self {
        Self {
            source,
            responses: Mutex::new(BTreeMap::new()),
            requests: AtomicUsize::new(0),
            sealed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl<R: RevocationFetcher> RevocationFetcher for RecordedCrls<'_, R> {
    async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError> {
        if let Some(crl) = self
            .responses
            .lock()
            .map_err(|_| CrlError::NoDistributionPoint)?
            .get(url)
            .cloned()
        {
            return Ok(crl);
        }
        if url.len() > 4096
            || self.sealed.load(Ordering::SeqCst)
            || self.requests.fetch_add(1, Ordering::SeqCst) >= 8
        {
            return Err(CrlError::NoDistributionPoint);
        }
        let crl = self.source.fetch_crl(url).await?;
        if crl.to_der().map_err(CrlError::Parse)?.len() > MAX_TOKEN {
            return Err(CrlError::NoDistributionPoint);
        }
        self.responses
            .lock()
            .map_err(|_| CrlError::NoDistributionPoint)?
            .insert(url.into(), crl.clone());
        Ok(crl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::io::Write;

    fn int(value: i64) -> Value {
        Value::Integer(value.into())
    }
    fn text(value: &str) -> Value {
        Value::Text(value.into())
    }
    fn encode(value: &Value) -> Vec<u8> {
        isomdl::cbor::to_vec(value).unwrap()
    }
    fn reference(identifier: bool) -> MdocStatusReference {
        if identifier {
            MdocStatusReference::IdentifierList {
                uri: "https://status.example/identifiers".into(),
                identifier: vec![7, 8],
                certificate_der: None,
            }
        } else {
            MdocStatusReference::StatusList {
                uri: "https://status.example/bits".into(),
                index: 3,
                certificate_der: None,
            }
        }
    }
    fn identifiers(ids: &[Vec<u8>]) -> Value {
        Value::Map(vec![(
            text("identifiers"),
            Value::Map(
                ids.iter()
                    .map(|id| (Value::Bytes(id.clone()), Value::Map(Vec::new())))
                    .collect(),
            ),
        )])
    }
    fn bits(raw: &[u8]) -> Value {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(raw).unwrap();
        Value::Map(vec![
            (text("bits"), int(1)),
            (text("lst"), Value::Bytes(encoder.finish().unwrap())),
        ])
    }
    fn fixture(identifier: bool) -> (Value, Value) {
        let public: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/mdoc_status_authority_public_chain.json"
        ))
        .unwrap();
        let leaf = STANDARD
            .decode(public["leaf_der_base64"].as_str().unwrap())
            .unwrap();
        let typ = if identifier {
            "application/identifierlist+cwt"
        } else {
            "application/statuslist+cwt"
        };
        let header = Value::Map(vec![
            (int(1), int(-7)),
            (int(16), text(typ)),
            (int(33), Value::Bytes(leaf)),
        ]);
        let reference = reference(identifier);
        let uri = match reference {
            MdocStatusReference::StatusList { uri, .. }
            | MdocStatusReference::IdentifierList { uri, .. } => uri,
        };
        let claim = if identifier {
            (int(65530), identifiers(&[vec![7, 8]]))
        } else {
            (int(65533), bits(&[8]))
        };
        let claims = Value::Map(vec![
            (int(2), text(&uri)),
            (int(6), int(1000)),
            (int(4), int(1300)),
            (int(65534), int(60)),
            claim,
        ]);
        (header, claims)
    }
    // Deliberately invalid signature. These fixtures exercise the codec and
    // refusal paths; they are never described as authenticated positive CWTs.
    fn envelope(header: &Value, claims: &Value, unprotected: Value) -> Vec<u8> {
        encode(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(encode(header)),
                unprotected,
                Value::Bytes(encode(claims)),
                Value::Bytes(vec![0; 64]),
            ])),
        ))
    }
    fn set(map: &mut Value, key: i64, value: Value) {
        let map = map.as_map_mut().unwrap();
        if let Some((_, existing)) = map.iter_mut().find(|(k, _)| *k == int(key)) {
            *existing = value;
        } else {
            map.push((int(key), value));
        }
    }

    #[test]
    fn separate_status_mechanisms_use_exact_bit_or_identifier() {
        for mechanism in [false, true] {
            let (header, claims) = fixture(mechanism);
            let parsed = ParsedToken::parse(
                &envelope(&header, &claims, Value::Map(Vec::new())),
                &reference(mechanism),
            )
            .unwrap();
            assert_eq!(parsed.status, MdocExternalStatus::Revoked);
            assert!(
                verify_signature(&parsed.cose, &parsed.chain).is_err(),
                "dummy signatures must never authenticate"
            );
            assert!(parsed
                .valid_until(OffsetDateTime::from_unix_timestamp(1001).unwrap())
                .is_ok());
            assert!(parsed
                .valid_until(OffsetDateTime::from_unix_timestamp(1060).unwrap())
                .is_err());
        }
        assert_eq!(
            identifier_status(&identifiers(&[vec![1], vec![2]]), &[7, 8]).unwrap(),
            MdocExternalStatus::Valid
        );
        assert_eq!(
            identifier_status(&identifiers(&[]), &[7, 8]).unwrap(),
            MdocExternalStatus::Valid
        );
        assert_eq!(
            bit_status(&bits(&[0]), 3).unwrap(),
            MdocExternalStatus::Valid
        );
        assert!(bit_status(&bits(&[0]), 8).is_err());
    }

    #[test]
    fn codec_rejects_duplicate_conflicting_and_critical_headers_and_claims() {
        let (header, claims) = fixture(false);
        for (label, value) in [
            (1, int(-7)),
            (2, Value::Array(Vec::new())),
            (16, text("application/statuslist+cwt")),
        ] {
            let unprotected = Value::Map(vec![(int(label), value)]);
            assert!(ParsedToken::parse(
                &envelope(&header, &claims, unprotected),
                &reference(false)
            )
            .is_err());
        }
        let mut duplicate = header.clone();
        duplicate.as_map_mut().unwrap().push((int(1), int(-7)));
        assert!(ParsedToken::parse(
            &envelope(&duplicate, &claims, Value::Map(Vec::new())),
            &reference(false)
        )
        .is_err());
        for label in [2, 4, 6, 65533] {
            let mut duplicate = claims.clone();
            let original = integer_member(duplicate.as_map().unwrap(), label)
                .unwrap()
                .clone();
            duplicate.as_map_mut().unwrap().push((int(label), original));
            assert!(ParsedToken::parse(
                &envelope(&header, &duplicate, Value::Map(Vec::new())),
                &reference(false)
            )
            .is_err());
        }
        let mut wrong = claims.clone();
        set(&mut wrong, 2, text("https://different.example/list"));
        assert!(ParsedToken::parse(
            &envelope(&header, &wrong, Value::Map(Vec::new())),
            &reference(false)
        )
        .is_err());
        assert!(ParsedToken::parse(
            &envelope(&header, &claims, Value::Map(Vec::new())),
            &reference(true)
        )
        .is_err());
    }

    #[test]
    fn freshness_requires_issuance_expiry_positive_ttl_and_no_future_nbf() {
        let (header, claims) = fixture(false);
        for (key, value) in [
            (6, 1002),
            (6, -1),
            (4, 1000),
            (4, 1001),
            (65534, 0),
            (65534, -1),
            (5, 1002),
        ] {
            let mut mutated = claims.clone();
            set(&mut mutated, key, int(value));
            let parsed = ParsedToken::parse(
                &envelope(&header, &mutated, Value::Map(Vec::new())),
                &reference(false),
            )
            .unwrap();
            assert!(parsed
                .valid_until(OffsetDateTime::from_unix_timestamp(1001).unwrap())
                .is_err());
        }
        for key in [4, 6] {
            let mut missing = claims.clone();
            missing
                .as_map_mut()
                .unwrap()
                .retain(|(k, _)| *k != int(key));
            assert!(ParsedToken::parse(
                &envelope(&header, &missing, Value::Map(Vec::new())),
                &reference(false)
            )
            .is_err());
        }
    }

    #[test]
    fn identifier_rfu_aggregation_and_malformed_maps_are_not_clear_status() {
        for malformed in [
            Value::Array(Vec::new()),
            Value::Map(Vec::new()),
            Value::Map(vec![(text("identifiers"), Value::Array(Vec::new()))]),
            Value::Map(vec![(
                text("identifiers"),
                Value::Map(vec![(text("not-bytes"), Value::Map(Vec::new()))]),
            )]),
            Value::Map(vec![(
                text("identifiers"),
                Value::Map(vec![(
                    Value::Bytes(vec![7, 8]),
                    Value::Map(vec![(text("rfu"), int(1))]),
                )]),
            )]),
            Value::Map(vec![
                (text("identifiers"), Value::Map(Vec::new())),
                (text("aggregation_uri"), text("https://elsewhere.example")),
            ]),
        ] {
            assert!(identifier_status(&malformed, &[7, 8]).is_err());
        }
        let duplicate = Value::Map(vec![(
            text("identifiers"),
            Value::Map(vec![
                (Value::Bytes(vec![7, 8]), Value::Map(Vec::new())),
                (Value::Bytes(vec![7, 8]), Value::Map(Vec::new())),
            ]),
        )]);
        assert!(decode(&encode(&duplicate), MAX_TOKEN).is_err());
    }

    #[test]
    fn compressed_and_cbor_resource_bounds_reject_truncation_trailing_and_bombs() {
        let mut value = bits(&[8]);
        let compressed = value
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("lst"))
            .unwrap()
            .1
            .as_bytes_mut()
            .unwrap();
        compressed.push(0);
        assert!(bit_status(&value, 3).is_err());
        let mut truncated = bits(&[8]);
        let compressed = truncated
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("lst"))
            .unwrap()
            .1
            .as_bytes_mut()
            .unwrap();
        compressed.truncate(compressed.len() - 4);
        assert!(bit_status(&truncated, 3).is_err());
        let mut malformed = bits(&[8]);
        malformed
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("lst"))
            .unwrap()
            .1 = Value::Bytes(vec![0x78]);
        assert!(bit_status(&malformed, 3).is_err());
        assert!(bit_status(&bits(&vec![0; MAX_LIST + 1]), 3).is_err());
        assert!(decode(&vec![0; MAX_TOKEN + 1], MAX_TOKEN).is_err());
        let mut nested = int(1);
        for _ in 0..40 {
            nested = Value::Array(vec![nested]);
        }
        assert!(decode(&encode(&nested), MAX_TOKEN).is_err());
        let mut trailing = encode(&int(1));
        trailing.extend(encode(&int(2)));
        assert!(decode(&trailing, MAX_TOKEN).is_err());
    }

    /// Real non-exportable signing for the original MSO, holder proof, CWT and
    /// CRL; the CRL transport and verifier clock are controlled test adapters.
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped certificate/holder signers"]
    fn managed_keys_verify_both_status_mechanisms_and_fail_closed() {
        use isomdl::cose::sign1::PreparedCoseSign1;
        use isomdl::definitions::{device_response::DeviceResponse, helpers::Tag24, Mso};
        use marty_crypto_test_support::{
            openbao_transit::DisposableOpenBao,
            remote_certificate::{RemoteCertificateAlgorithm, RemoteCertificateKey},
        };
        use rcgen::{CertificateParams, DnType, KeyUsagePurpose, SigningKey};
        use std::sync::{atomic::AtomicI64, Arc};

        fn sign(prepared: PreparedCoseSign1, key: &RemoteCertificateKey) -> MaybeTagged<CoseSign1> {
            let der = key.sign(prepared.signature_payload()).unwrap();
            let signature = p256::ecdsa::Signature::from_der(&der).unwrap();
            prepared.finalize(signature.to_bytes().to_vec())
        }
        fn root(name: &str) -> (CertificateParams, RemoteCertificateKey, rcgen::Certificate) {
            let key = RemoteCertificateKey::new(RemoteCertificateAlgorithm::Es256);
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let certificate = params.self_signed(&key).unwrap();
            (params, key, certificate)
        }
        fn leaf(
            name: &str,
            root: &CertificateParams,
            root_key: &RemoteCertificateKey,
            crl_url: &str,
        ) -> (RemoteCertificateKey, rcgen::Certificate) {
            let key = RemoteCertificateKey::new(RemoteCertificateAlgorithm::Es256);
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.use_authority_key_identifier_extension = true;
            params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
                uris: vec![crl_url.into()],
            }];
            let certificate = params
                .signed_by(&key, &rcgen::Issuer::from_params(root, root_key))
                .unwrap();
            (key, certificate)
        }
        fn crl(
            params: &CertificateParams,
            key: &RemoteCertificateKey,
            now: OffsetDateTime,
            signer: &[u8],
            revoked: bool,
            stale: bool,
        ) -> CertificateList {
            let certificate = Certificate::from_der(signer).unwrap();
            let revoked_certs = if revoked {
                vec![rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from_slice(
                        certificate.tbs_certificate.serial_number.as_bytes(),
                    ),
                    revocation_time: now - time::Duration::seconds(30),
                    reason_code: None,
                    invalidity_date: None,
                }]
            } else {
                Vec::new()
            };
            let next_update = if stale {
                now - time::Duration::seconds(1)
            } else {
                now + time::Duration::seconds(300)
            };
            let crl = rcgen::CertificateRevocationListParams {
                this_update: now - time::Duration::seconds(60),
                next_update,
                crl_number: 1u64.into(),
                issuing_distribution_point: None,
                revoked_certs,
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(&rcgen::Issuer::from_params(params, key))
            .unwrap();
            CertificateList::from_der(crl.der()).unwrap()
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Transcript(Value);
        impl isomdl::definitions::session::SessionTranscript for Transcript {}

        let bao = DisposableOpenBao::from_marked_env();
        let (root_a_params, root_a_key, root_a) = root("isolated mdoc status IACA A");
        let (root_b_params, root_b_key, root_b) = root("isolated signed status delegate B");
        let url_a = "https://crl.fixture.invalid/a.crl";
        let url_b = "https://crl.fixture.invalid/b.crl";
        let (document_key, document_certificate) = leaf(
            "isolated mdoc document signer A",
            &root_a_params,
            &root_a_key,
            url_a,
        );
        let (delegate_key, delegate_certificate) = leaf(
            "isolated status signer B",
            &root_b_params,
            &root_b_key,
            url_b,
        );
        let holder = bao.create_es256();
        let point = holder.verifying_key().to_sec1_point(false);
        let holder_key = isomdl::definitions::device_key::CoseKey::EC2 {
            crv: isomdl::definitions::device_key::EC2Curve::P256,
            x: point.x().unwrap().to_vec(),
            y: isomdl::definitions::device_key::cose_key::EC2Y::Value(point.y().unwrap().to_vec()),
        };
        let source: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        let original = STANDARD
            .decode(source["response_b64"].as_str().unwrap())
            .unwrap();
        let transcript = STANDARD
            .decode(source["transcript_b64"].as_str().unwrap())
            .unwrap();
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let uri = "https://status.fixture.invalid/list";
        let prepare = |identifier: bool| {
            let mut response: DeviceResponse = isomdl::cbor::from_slice(&original).unwrap();
            let mut documents = response.documents.take().unwrap().into_inner();
            let document = &mut documents[0];
            let mut mso: Mso = isomdl::cbor::from_slice::<Tag24<Mso>>(
                document.issuer_signed.issuer_auth.payload.as_ref().unwrap(),
            )
            .unwrap()
            .into_inner();
            mso.device_key_info.device_key = holder_key.clone();
            mso.validity_info.signed = now - time::Duration::seconds(1);
            mso.validity_info.valid_from = now - time::Duration::seconds(1);
            mso.validity_info.valid_until = now + time::Duration::seconds(600);
            mso.status = Some(if identifier {
                isomdl::definitions::Status {
                    status_list: None,
                    identifier_list: Some(isomdl::definitions::IdentifierListInfo {
                        id: vec![7, 8].into(),
                        uri: uri.into(),
                        certificate: Some(root_b.der().to_vec().into()),
                    }),
                }
            } else {
                isomdl::definitions::Status {
                    identifier_list: None,
                    status_list: Some(isomdl::definitions::StatusListInfo {
                        idx: 3,
                        uri: uri.into(),
                        certificate: None,
                    }),
                }
            });
            let issuer = PreparedCoseSign1::new(
                coset::CoseSign1Builder::new()
                    .protected(
                        coset::HeaderBuilder::new()
                            .algorithm(iana::Algorithm::ES256)
                            .build(),
                    )
                    .unprotected(
                        coset::HeaderBuilder::new()
                            .value(
                                33,
                                Value::Array(vec![
                                    Value::Bytes(document_certificate.der().to_vec()),
                                    Value::Bytes(root_a.der().to_vec()),
                                ]),
                            )
                            .build(),
                    )
                    .payload(isomdl::cbor::to_vec(&Tag24::new(mso).unwrap()).unwrap()),
                None,
                None,
                true,
            )
            .unwrap();
            document.issuer_signed.issuer_auth = sign(issuer, &document_key);
            let auth = isomdl::definitions::device_signed::DeviceAuthentication::new(
                Transcript(isomdl::cbor::from_slice(&transcript).unwrap()),
                document.doc_type.clone(),
                document.device_signed.namespaces.clone(),
            );
            let detached = isomdl::cbor::to_vec(&Tag24::new(auth).unwrap()).unwrap();
            let holder_proof = PreparedCoseSign1::new(
                coset::CoseSign1Builder::new().protected(
                    coset::HeaderBuilder::new()
                        .algorithm(iana::Algorithm::ES256)
                        .build(),
                ),
                Some(&detached),
                None,
                false,
            )
            .unwrap();
            let signature = holder.sign_es256(holder_proof.signature_payload()).unwrap();
            document.device_signed.device_auth =
                isomdl::definitions::device_signed::DeviceAuth::DeviceSignature(
                    holder_proof.finalize(signature),
                );
            response.documents = Some(documents.try_into().unwrap());
            let encoded = isomdl::cbor::to_vec(&response).unwrap();
            let roots = if identifier {
                vec![root_a.pem()]
            } else {
                vec![root_a.pem(), root_b.pem()]
            };
            let mut requests = super::super::prepare_mdoc_status_requests_at(
                &encoded,
                &transcript,
                &roots,
                &[],
                now,
            )
            .unwrap();
            assert_eq!(requests.len(), 1);
            requests.remove(0)
        };
        let bit_request = prepare(false);
        let identifier_request = prepare(true);
        let token = |identifier: bool,
                     revoked: bool,
                     key: &RemoteCertificateKey,
                     certificate: &rcgen::Certificate,
                     root: &rcgen::Certificate,
                     subject: &str| {
            let list_claim = if identifier {
                (
                    int(65530),
                    identifiers(&[if revoked { vec![7, 8] } else { vec![1, 2] }]),
                )
            } else {
                (int(65533), bits(&[if revoked { 8 } else { 0 }]))
            };
            let claims = Value::Map(vec![
                (int(2), text(subject)),
                (int(6), int(now.unix_timestamp())),
                (int(4), int(now.unix_timestamp() + 120)),
                (int(65534), int(60)),
                list_claim,
            ]);
            let typ = if identifier {
                "application/identifierlist+cwt"
            } else {
                "application/statuslist+cwt"
            };
            let prepared = PreparedCoseSign1::new(
                coset::CoseSign1Builder::new()
                    .protected(
                        coset::HeaderBuilder::new()
                            .algorithm(iana::Algorithm::ES256)
                            .value(16, text(typ))
                            .value(
                                33,
                                Value::Array(vec![
                                    Value::Bytes(certificate.der().to_vec()),
                                    Value::Bytes(root.der().to_vec()),
                                ]),
                            )
                            .build(),
                    )
                    .payload(encode(&claims)),
                None,
                None,
                true,
            )
            .unwrap();
            isomdl::cbor::to_vec(&sign(prepared, key)).unwrap()
        };
        struct CrlTransport {
            crls: BTreeMap<String, CertificateList>,
            fail: bool,
            clock: Arc<AtomicI64>,
            advance: i64,
            calls: AtomicUsize,
        }
        #[async_trait]
        impl RevocationFetcher for CrlTransport {
            async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.clock.fetch_add(self.advance, Ordering::SeqCst);
                if self.fail {
                    return Err(CrlError::NoDistributionPoint);
                }
                self.crls
                    .get(url)
                    .cloned()
                    .ok_or(CrlError::NoDistributionPoint)
            }
        }
        let good_a = crl(
            &root_a_params,
            &root_a_key,
            now,
            document_certificate.der(),
            false,
            false,
        );
        let good_b = crl(
            &root_b_params,
            &root_b_key,
            now,
            delegate_certificate.der(),
            false,
            false,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let check = |request: &AuthenticatedMdocStatusRequest,
                     bytes: &[u8],
                     a: CertificateList,
                     b: CertificateList,
                     fail: bool,
                     advance: i64| {
            let clock = Arc::new(AtomicI64::new(now.unix_timestamp()));
            let transport = CrlTransport {
                crls: BTreeMap::from([(url_a.into(), a), (url_b.into(), b)]),
                fail,
                clock: clock.clone(),
                advance,
                calls: AtomicUsize::new(0),
            };
            let result = runtime.block_on(verify_mdoc_external_status(
                request,
                bytes,
                &transport,
                || OffsetDateTime::from_unix_timestamp(clock.load(Ordering::SeqCst)).unwrap(),
            ));
            // A second verification must consume only its sealed CRL snapshot.
            assert!(transport.calls.load(Ordering::SeqCst) <= 1);
            result
        };
        for identifier in [false, true] {
            let (request, key, certificate, root) = if identifier {
                (
                    &identifier_request,
                    &delegate_key,
                    &delegate_certificate,
                    &root_b,
                )
            } else {
                (&bit_request, &document_key, &document_certificate, &root_a)
            };
            for revoked in [false, true] {
                let bytes = token(identifier, revoked, key, certificate, root, uri);
                let observed =
                    check(request, &bytes, good_a.clone(), good_b.clone(), false, 0).unwrap();
                assert_eq!(
                    observed.status_for(request).unwrap(),
                    if revoked {
                        MdocExternalStatus::Revoked
                    } else {
                        MdocExternalStatus::Valid
                    }
                );
                let other = if identifier {
                    &bit_request
                } else {
                    &identifier_request
                };
                assert!(observed.status_for(other).is_err());
                assert!(check(request, &bytes, good_a.clone(), good_b.clone(), true, 0).is_err());
                assert!(check(request, &bytes, good_a.clone(), good_b.clone(), false, 61).is_err());
            }
            let wrong_subject = token(
                identifier,
                false,
                key,
                certificate,
                root,
                "https://other.fixture.invalid/list",
            );
            assert!(check(
                request,
                &wrong_subject,
                good_a.clone(),
                good_b.clone(),
                false,
                0
            )
            .is_err());
        }
        let bytes = token(
            false,
            false,
            &document_key,
            &document_certificate,
            &root_a,
            uri,
        );
        let stale = crl(
            &root_a_params,
            &root_a_key,
            now,
            document_certificate.der(),
            false,
            true,
        );
        assert!(check(&bit_request, &bytes, stale, good_b.clone(), false, 0).is_err());
        let revoked = crl(
            &root_a_params,
            &root_a_key,
            now,
            document_certificate.der(),
            true,
            false,
        );
        assert!(check(&bit_request, &bytes, revoked, good_b.clone(), false, 0).is_err());
        let other_authority = token(
            false,
            false,
            &delegate_key,
            &delegate_certificate,
            &root_b,
            uri,
        );
        assert!(check(
            &bit_request,
            &other_authority,
            good_a.clone(),
            good_b.clone(),
            false,
            0
        )
        .is_err());
        let wrong_key = token(
            false,
            false,
            &delegate_key,
            &document_certificate,
            &root_a,
            uri,
        );
        assert!(check(
            &bit_request,
            &wrong_key,
            good_a.clone(),
            good_b.clone(),
            false,
            0
        )
        .is_err());
        assert!(check(&identifier_request, &bytes, good_a, good_b, false, 0).is_err());
    }
}
