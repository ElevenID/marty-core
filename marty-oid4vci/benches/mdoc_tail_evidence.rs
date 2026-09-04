#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        collections::{HashMap, HashSet},
        env,
        hint::black_box,
        time::{Duration, Instant},
    };

    use base64::Engine;
    use ciborium::Value as CborValue;
    use isomdl::definitions::IssuerSigned;
    use marty_oid4vci::{
        formats::mdoc::{assemble_mdoc, PreparedMdoc},
        remote_credential::{prepare_remote_mdoc_batch, RemoteMdocBatchItem, RemoteMdocRequest},
        types::SignedCredential,
    };
    use sha2::{Digest, Sha256};

    const ENABLE_ENV: &str = "MARTY_MDOC_TAIL_EVIDENCE";
    const MATRIX_CLASSES_ENV: &str = "MARTY_MDOC_MATRIX_CLASSES";
    const MATRIX_ITEM_COUNTS_ENV: &str = "MARTY_MDOC_MATRIX_ITEM_COUNTS";
    const MATRIX_BATCH_SIZES_ENV: &str = "MARTY_MDOC_MATRIX_BATCH_SIZES";
    const SAMPLES_ENV: &str = "MARTY_MDOC_TAIL_SAMPLES";
    const WARMUP_ENV: &str = "MARTY_MDOC_TAIL_WARMUP_INVOCATIONS";
    const EVIDENCE_GROUP: &str = "mdoc_invocation_tail";
    const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
    const NAMESPACE: &str = "org.iso.18013.5.1";
    const CBOR_TAG_ENCODED_CBOR: u64 = 24;
    const LARGE_PORTRAIT_BYTES: usize = 256 * 1024;
    const MIXED_MEDIUM_BYTES: usize = 1024;
    const MIXED_LARGE_BYTES: usize = 64 * 1024;
    const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
    const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
    const DEFAULT_SAMPLES: usize = 200;
    const MIN_SAMPLES: usize = 100;
    const MAX_SAMPLES: usize = 10_000;
    const DEFAULT_WARMUP_INVOCATIONS: usize = 10;
    const MIN_WARMUP_INVOCATIONS: usize = 1;
    const MAX_WARMUP_INVOCATIONS: usize = 1_000;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PayloadClass {
        SmallPrimitive,
        MediumNested,
        LargePortrait,
        MixedSize,
    }

    impl PayloadClass {
        const ALL: [Self; 4] = [
            Self::SmallPrimitive,
            Self::MediumNested,
            Self::LargePortrait,
            Self::MixedSize,
        ];

        const fn label(self) -> &'static str {
            match self {
                Self::SmallPrimitive => "small_primitive",
                Self::MediumNested => "medium_nested",
                Self::LargePortrait => "large_portrait",
                Self::MixedSize => "mixed_size",
            }
        }

        const fn code(self) -> u64 {
            match self {
                Self::SmallPrimitive => 1,
                Self::MediumNested => 2,
                Self::LargePortrait => 3,
                Self::MixedSize => 4,
            }
        }

        fn parse(value: &str) -> Option<Self> {
            match value {
                "small_primitive" => Some(Self::SmallPrimitive),
                "medium_nested" => Some(Self::MediumNested),
                "large_portrait" => Some(Self::LargePortrait),
                "mixed_size" => Some(Self::MixedSize),
                _ => None,
            }
        }
    }

    struct Selection {
        classes: Vec<PayloadClass>,
        item_counts: Vec<usize>,
        batch_sizes: Vec<usize>,
    }

    impl Selection {
        fn from_env() -> Result<Self, String> {
            Ok(Self {
                classes: parse_named_selector(
                    MATRIX_CLASSES_ENV,
                    &PayloadClass::ALL,
                    PayloadClass::label,
                    PayloadClass::parse,
                )?,
                item_counts: parse_numeric_selector(MATRIX_ITEM_COUNTS_ENV, &ITEM_COUNTS)?,
                batch_sizes: parse_numeric_selector(MATRIX_BATCH_SIZES_ENV, &BATCH_SIZES)?,
            })
        }
    }

    #[derive(Clone, Copy)]
    struct Settings {
        samples: usize,
        warmup_invocations: usize,
    }

    impl Settings {
        fn from_env() -> Result<Self, String> {
            Ok(Self {
                samples: parse_bounded_setting(
                    SAMPLES_ENV,
                    DEFAULT_SAMPLES,
                    MIN_SAMPLES,
                    MAX_SAMPLES,
                )?,
                warmup_invocations: parse_bounded_setting(
                    WARMUP_ENV,
                    DEFAULT_WARMUP_INVOCATIONS,
                    MIN_WARMUP_INVOCATIONS,
                    MAX_WARMUP_INVOCATIONS,
                )?,
            })
        }
    }

    fn evidence_enabled() -> Result<bool, String> {
        match env::var(ENABLE_ENV) {
            Ok(value) if value == "1" => Ok(true),
            Ok(value) => Err(format!(
                "{ENABLE_ENV} must equal 1 when set; received '{value}'"
            )),
            Err(env::VarError::NotPresent) => Ok(false),
            Err(env::VarError::NotUnicode(_)) => {
                Err(format!("{ENABLE_ENV} must contain Unicode text"))
            }
        }
    }

    fn selector_values(name: &str) -> Result<Option<Vec<String>>, String> {
        let value = match env::var(name) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(format!("{name} must contain Unicode text"));
            }
        };
        let values = value
            .split(',')
            .map(|value| {
                if value.is_empty() || value.trim().is_empty() {
                    Err(format!("{name} contains an empty value"))
                } else {
                    Ok(value.trim().to_owned())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.is_empty() {
            return Err(format!("{name} must select at least one value"));
        }
        if values.iter().any(|value| value == "all") {
            if values != ["all"] {
                return Err(format!("{name}=all cannot be combined with values"));
            }
            Ok(None)
        } else {
            Ok(Some(values))
        }
    }

    fn parse_named_selector<T: Copy + Eq>(
        name: &str,
        allowed: &[T],
        label: impl Fn(T) -> &'static str,
        parse: impl Fn(&str) -> Option<T>,
    ) -> Result<Vec<T>, String> {
        let Some(values) = selector_values(name)? else {
            return Ok(allowed.to_vec());
        };
        let selected = values
            .iter()
            .map(|value| {
                parse(value).ok_or_else(|| {
                    format!(
                        "unsupported {name} value '{value}'; expected one of {}",
                        allowed
                            .iter()
                            .copied()
                            .map(&label)
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(name, &selected, |value| label(value).to_owned())?;
        Ok(selected)
    }

    fn parse_numeric_selector(name: &str, allowed: &[usize]) -> Result<Vec<usize>, String> {
        let Some(values) = selector_values(name)? else {
            return Ok(allowed.to_vec());
        };
        let selected = values
            .iter()
            .map(|value| {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("{name} value '{value}' is not an integer"))?;
                if parsed.to_string() != *value {
                    return Err(format!("{name} value '{value}' is not canonical"));
                }
                if !allowed.contains(&parsed) {
                    return Err(format!(
                        "unsupported {name} value '{value}'; expected one of {}",
                        allowed
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                }
                Ok(parsed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(name, &selected, |value| value.to_string())?;
        Ok(selected)
    }

    fn ensure_unique<T: Copy + Eq>(
        name: &str,
        values: &[T],
        label: impl Fn(T) -> String,
    ) -> Result<(), String> {
        for (ordinal, value) in values.iter().copied().enumerate() {
            if values[..ordinal].contains(&value) {
                return Err(format!("{name} repeats '{}'", label(value)));
            }
        }
        Ok(())
    }

    fn parse_bounded_setting(
        name: &str,
        default: usize,
        minimum: usize,
        maximum: usize,
    ) -> Result<usize, String> {
        let value = match env::var(name) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(default),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(format!("{name} must contain Unicode text"));
            }
        };
        let parsed = value
            .parse::<usize>()
            .map_err(|_| format!("{name} value '{value}' is not an integer"))?;
        if parsed.to_string() != value {
            return Err(format!("{name} value '{value}' is not canonical"));
        }
        if !(minimum..=maximum).contains(&parsed) {
            return Err(format!(
                "{name} must be between {minimum} and {maximum}; received {parsed}"
            ));
        }
        Ok(parsed)
    }

    fn claim_name(index: usize) -> String {
        format!("benchmark_claim_{index:04}")
    }

    fn repeated_ascii(length: usize, index: usize) -> String {
        let byte = b'A' + u8::try_from(index % 26).expect("fixture alphabet index must fit u8");
        String::from_utf8(vec![byte; length]).expect("fixture bytes must be ASCII")
    }

    fn json_value(class: PayloadClass, index: usize) -> serde_json::Value {
        match class {
            PayloadClass::SmallPrimitive => match index % 4 {
                0 => serde_json::json!(index),
                1 => serde_json::json!(index.is_multiple_of(2)),
                2 => serde_json::json!(format!("value-{index:04}")),
                _ => serde_json::Value::Null,
            },
            PayloadClass::MediumNested => serde_json::json!({
                "group": index % 8,
                "metadata": {
                    "enabled": index.is_multiple_of(2),
                    "label": format!("nested-{index:04}"),
                    "sequence": index
                },
                "values": [index, index + 1, index + 2, index + 3]
            }),
            PayloadClass::LargePortrait if index == 0 => {
                serde_json::Value::String(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
            }
            PayloadClass::LargePortrait => serde_json::Value::String(format!("value-{index:04}")),
            PayloadClass::MixedSize => match index % 4 {
                0 if index == 0 => {
                    serde_json::Value::String(repeated_ascii(MIXED_LARGE_BYTES, index))
                }
                0 => serde_json::Value::String(repeated_ascii(MIXED_MEDIUM_BYTES, index)),
                1 => serde_json::json!({
                    "flags": [true, false, index.is_multiple_of(2)],
                    "sequence": index
                }),
                2 => serde_json::json!(index),
                _ => serde_json::Value::String(format!("mixed-{index:04}")),
            },
        }
    }

    fn cbor_integer(value: usize) -> CborValue {
        CborValue::Integer(
            u64::try_from(value)
                .expect("fixture integer must fit u64")
                .into(),
        )
    }

    fn expected_cbor_value(class: PayloadClass, index: usize) -> CborValue {
        match class {
            PayloadClass::SmallPrimitive => match index % 4 {
                0 => cbor_integer(index),
                1 => CborValue::Bool(index.is_multiple_of(2)),
                2 => CborValue::Text(format!("value-{index:04}")),
                _ => CborValue::Null,
            },
            PayloadClass::MediumNested => CborValue::Map(vec![
                (CborValue::Text("group".into()), cbor_integer(index % 8)),
                (
                    CborValue::Text("metadata".into()),
                    CborValue::Map(vec![
                        (
                            CborValue::Text("enabled".into()),
                            CborValue::Bool(index.is_multiple_of(2)),
                        ),
                        (
                            CborValue::Text("label".into()),
                            CborValue::Text(format!("nested-{index:04}")),
                        ),
                        (CborValue::Text("sequence".into()), cbor_integer(index)),
                    ]),
                ),
                (
                    CborValue::Text("values".into()),
                    CborValue::Array((index..index + 4).map(cbor_integer).collect()),
                ),
            ]),
            PayloadClass::LargePortrait if index == 0 => {
                CborValue::Text(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
            }
            PayloadClass::LargePortrait => CborValue::Text(format!("value-{index:04}")),
            PayloadClass::MixedSize => match index % 4 {
                0 if index == 0 => CborValue::Text(repeated_ascii(MIXED_LARGE_BYTES, index)),
                0 => CborValue::Text(repeated_ascii(MIXED_MEDIUM_BYTES, index)),
                1 => CborValue::Map(vec![
                    (
                        CborValue::Text("flags".into()),
                        CborValue::Array(vec![
                            CborValue::Bool(true),
                            CborValue::Bool(false),
                            CborValue::Bool(index.is_multiple_of(2)),
                        ]),
                    ),
                    (CborValue::Text("sequence".into()), cbor_integer(index)),
                ]),
                2 => cbor_integer(index),
                _ => CborValue::Text(format!("mixed-{index:04}")),
            },
        }
    }

    fn credential_id(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        credential_ordinal: usize,
    ) -> String {
        let tail = (class.code() << 40)
            | (u64::try_from(item_count).unwrap() << 24)
            | (u64::try_from(batch_size).unwrap() << 12)
            | u64::try_from(credential_ordinal).unwrap();
        format!(
            "urn:uuid:{:08x}-{item_count:04x}-4{batch_size:03x}-8{credential_ordinal:03x}-{tail:012x}",
            class.code()
        )
    }

    fn batch_id(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        credential_ordinal: usize,
    ) -> u64 {
        (class.code() << 56)
            | (u64::try_from(item_count).unwrap() << 40)
            | (u64::try_from(batch_size).unwrap() << 24)
            | u64::try_from(credential_ordinal).unwrap()
    }

    fn request(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        credential_ordinal: usize,
    ) -> RemoteMdocRequest {
        let claims = (0..item_count)
            .map(|index| (claim_name(index), json_value(class, index)))
            .collect::<HashMap<_, _>>();
        if class == PayloadClass::LargePortrait {
            assert_eq!(
                claims
                    .values()
                    .filter(|value| {
                        matches!(value, serde_json::Value::String(value) if value.len() == LARGE_PORTRAIT_BYTES)
                    })
                    .count(),
                1,
                "large portrait fixtures must contain exactly one 256-KiB value per credential"
            );
        }

        RemoteMdocRequest {
            issuer_id: format!(
                "did:example:tail-evidence-issuer:{}:{item_count}:{batch_size}:{credential_ordinal}",
                class.label()
            ),
            algorithm: "ES256".into(),
            credential_type: DOC_TYPE.into(),
            namespace: NAMESPACE.into(),
            claims,
            expiration_seconds: Some(365 * 86_400),
            credential_id: Some(credential_id(
                class,
                item_count,
                batch_size,
                credential_ordinal,
            )),
            holder_jwk: Some(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            })),
        }
    }

    fn fixture(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
    ) -> Vec<RemoteMdocBatchItem> {
        (0..batch_size)
            .map(|credential_ordinal| {
                RemoteMdocBatchItem::new(
                    batch_id(class, item_count, batch_size, credential_ordinal),
                    request(class, item_count, batch_size, credential_ordinal),
                )
            })
            .collect()
    }

    fn map_value<'a>(entries: &'a [(CborValue, CborValue)], name: &str) -> &'a CborValue {
        entries
            .iter()
            .find_map(|(key, value)| (key == &CborValue::Text(name.to_owned())).then_some(value))
            .unwrap_or_else(|| panic!("{name} must be present"))
    }

    fn claim_index(identifier: &str, item_count: usize) -> usize {
        let encoded = identifier
            .strip_prefix("benchmark_claim_")
            .unwrap_or_else(|| panic!("unexpected tail-evidence claim identifier {identifier}"));
        let index = encoded
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("tail-evidence claim identifier must end in an integer"));
        assert_eq!(
            identifier,
            claim_name(index),
            "tail-evidence claim identifier must be canonical"
        );
        assert!(index < item_count, "claim index must be in range");
        index
    }

    fn assert_prepared(
        class: PayloadClass,
        item_count: usize,
        expected_credential_id: &str,
        prepared: PreparedMdoc,
    ) {
        assert_eq!(prepared.credential_id, expected_credential_id);
        let credential = assemble_mdoc(prepared, &[0xa5; 64])
            .expect("tail-evidence fixture must assemble for preflight");
        let SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } = credential
        else {
            panic!("tail-evidence fixture must produce mso_mdoc")
        };
        assert_eq!(credential_id, expected_credential_id);

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(issuer_signed_b64)
            .expect("tail-evidence IssuerSigned must be base64url");
        let issuer_signed: IssuerSigned =
            isomdl::cbor::from_slice(&bytes).expect("tail-evidence IssuerSigned must decode");
        let mso_bytes = issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .expect("tail-evidence issuerAuth payload must be present");
        let namespaces = issuer_signed
            .namespaces
            .as_ref()
            .expect("tail-evidence nameSpaces must be present");
        assert_eq!(namespaces.len(), 1, "fixture must have one namespace");
        let items = namespaces
            .get(NAMESPACE)
            .expect("tail-evidence namespace must be present");
        assert_eq!(items.len(), item_count, "fixture must contain no decoys");

        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) =
            isomdl::cbor::from_slice::<CborValue>(mso_bytes)
                .expect("MobileSecurityObjectBytes must decode")
        else {
            panic!("MobileSecurityObjectBytes must use tag 24")
        };
        let CborValue::Bytes(encoded_mso) = *encoded_mso else {
            panic!("MobileSecurityObjectBytes tag 24 must wrap bytes")
        };
        let CborValue::Map(mso) = isomdl::cbor::from_slice::<CborValue>(&encoded_mso)
            .expect("MobileSecurityObject must decode")
        else {
            panic!("MobileSecurityObject must be a map")
        };
        assert_eq!(
            map_value(&mso, "digestAlgorithm"),
            &CborValue::Text("SHA-256".into())
        );
        assert_eq!(
            map_value(&mso, "docType"),
            &CborValue::Text(DOC_TYPE.into())
        );
        let CborValue::Map(value_digests) = map_value(&mso, "valueDigests") else {
            panic!("valueDigests must be a map")
        };
        assert_eq!(value_digests.len(), 1, "MSO must have one namespace");
        let CborValue::Map(namespace_digests) = value_digests
            .iter()
            .find_map(|(key, value)| (key == &CborValue::Text(NAMESPACE.into())).then_some(value))
            .expect("namespace valueDigests must be present")
        else {
            panic!("namespace valueDigests must be a map")
        };
        assert_eq!(
            namespace_digests.len(),
            item_count,
            "MSO must contain no decoy digests"
        );

        let mut seen_claims = HashSet::with_capacity(item_count);
        let mut seen_digests = HashSet::with_capacity(item_count);
        for (expected_digest_id, tagged_item) in items.iter().enumerate() {
            let item = tagged_item.as_ref();
            let digest_id = serde_json::to_value(item.digest_id)
                .expect("digest ID must serialize")
                .as_u64()
                .expect("digest ID must be unsigned");
            assert_eq!(digest_id, expected_digest_id as u64);
            assert!(seen_digests.insert(digest_id), "digest IDs must be unique");
            let CborValue::Bytes(expected_digest) = namespace_digests
                .iter()
                .find_map(|(key, value)| {
                    (key == &CborValue::Integer(digest_id.into())).then_some(value)
                })
                .expect("every item digest ID must be present in the MSO")
            else {
                panic!("valueDigest must be bytes")
            };
            let encoded_wrapper =
                isomdl::cbor::to_vec(tagged_item).expect("tag-24 item must encode");
            assert_eq!(
                Sha256::digest(encoded_wrapper).as_slice(),
                expected_digest,
                "MSO must commit to the complete tag-24 item"
            );

            let index = claim_index(&item.element_identifier, item_count);
            assert!(
                seen_claims.insert(index),
                "claim identifiers must be unique"
            );
            assert_eq!(
                item.element_value,
                expected_cbor_value(class, index),
                "item must preserve its independently constructed CBOR value"
            );
        }
        assert_eq!(seen_claims.len(), item_count);
        assert_eq!(seen_digests.len(), item_count);
    }

    fn preflight(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        fixture: &[RemoteMdocBatchItem],
    ) -> Result<(), String> {
        let prepared = prepare_remote_mdoc_batch(fixture.to_vec())
            .map_err(|_| "public mdoc batch preparation failed during preflight".to_owned())?;
        if prepared.len() != batch_size {
            return Err("preflight result count did not match batch size".to_owned());
        }

        let mut expected_batch_ids = HashSet::with_capacity(batch_size);
        let mut expected_credential_ids = HashSet::with_capacity(batch_size);
        for (credential_ordinal, prepared) in prepared.into_iter().enumerate() {
            let expected_batch_id = batch_id(class, item_count, batch_size, credential_ordinal);
            let expected_credential_id =
                credential_id(class, item_count, batch_size, credential_ordinal);
            assert!(
                expected_batch_ids.insert(expected_batch_id),
                "routing identities must be unique"
            );
            assert!(
                expected_credential_ids.insert(expected_credential_id.clone()),
                "credential identities must be unique"
            );
            assert_eq!(
                prepared.batch_id(),
                expected_batch_id,
                "batch results must preserve caller order and identity"
            );
            assert_prepared(
                class,
                item_count,
                &expected_credential_id,
                prepared.into_prepared_mdoc(),
            );
        }
        Ok(())
    }

    fn nearest_rank(sorted: &[Duration], percentile: usize) -> Duration {
        assert!(!sorted.is_empty());
        assert!((1..=100).contains(&percentile));
        let rank = (percentile * sorted.len()).div_ceil(100);
        sorted[rank - 1]
    }

    fn assert_nearest_rank_oracle() {
        let samples = (1..=100).map(Duration::from_nanos).collect::<Vec<_>>();
        assert_eq!(nearest_rank(&samples, 50), Duration::from_nanos(50));
        assert_eq!(nearest_rank(&samples, 95), Duration::from_nanos(95));
        assert_eq!(nearest_rank(&samples, 99), Duration::from_nanos(99));
    }

    fn measure(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        settings: Settings,
        fixture: &[RemoteMdocBatchItem],
    ) -> Result<(), String> {
        for _ in 0..settings.warmup_invocations {
            let invocation = fixture.to_vec();
            let prepared = prepare_remote_mdoc_batch(black_box(invocation))
                .map_err(|_| "public mdoc batch preparation failed during warm-up".to_owned())?;
            black_box(&prepared);
        }

        let mut samples = Vec::with_capacity(settings.samples);
        for _ in 0..settings.samples {
            let invocation = fixture.to_vec();
            let started = Instant::now();
            let outcome = prepare_remote_mdoc_batch(black_box(invocation));
            black_box(&outcome);
            let elapsed = started.elapsed();
            let prepared = outcome.map_err(|_| {
                "public mdoc batch preparation failed during measurement".to_owned()
            })?;
            samples.push(elapsed);
            drop(prepared);
        }
        assert_eq!(samples.len(), settings.samples);
        samples.sort_unstable();

        println!(
            "{EVIDENCE_GROUP}/{}/n={item_count}/b={batch_size} samples={} warmup={} method=nearest_rank unit=ns p50={} p95={} p99={}",
            class.label(),
            settings.samples,
            settings.warmup_invocations,
            nearest_rank(&samples, 50).as_nanos(),
            nearest_rank(&samples, 95).as_nanos(),
            nearest_rank(&samples, 99).as_nanos(),
        );
        Ok(())
    }

    pub fn run() -> Result<(), String> {
        if !evidence_enabled()? {
            println!("mdoc invocation-tail evidence disabled; set {ENABLE_ENV}=1 to opt in");
            return Ok(());
        }
        if cfg!(debug_assertions) {
            return Err(
                "mdoc invocation-tail evidence requires an optimized cargo bench build".to_owned(),
            );
        }

        // Validate every selector and sample setting before allocating any payload fixture.
        let selection = Selection::from_env()?;
        let settings = Settings::from_env()?;
        assert_nearest_rank_oracle();

        println!(
            "mdoc_invocation_tail_evidence schema=1 target_os={} target_arch={} samples={} warmup={} method=nearest_rank unit=ns",
            env::consts::OS,
            env::consts::ARCH,
            settings.samples,
            settings.warmup_invocations,
        );
        for class in selection.classes {
            for &item_count in &selection.item_counts {
                for &batch_size in &selection.batch_sizes {
                    let fixture = fixture(class, item_count, batch_size);
                    preflight(class, item_count, batch_size, &fixture)?;
                    measure(class, item_count, batch_size, settings, &fixture)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("mdoc_tail_evidence: {error}");
        std::process::exit(2);
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("mdoc_tail_evidence is a native-only evidence binary");
    std::process::exit(2);
}
