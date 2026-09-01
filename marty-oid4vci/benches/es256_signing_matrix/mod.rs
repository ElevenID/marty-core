use std::collections::HashMap;

use marty_oid4vci::types::{CredentialClaims, CredentialPayloadFormat};

pub const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
pub const MATRIX_BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];

const MATRIX_ENABLE_ENV: &str = "MARTY_ES256_MATRIX";
const MATRIX_FORMATS_ENV: &str = "MARTY_ES256_MATRIX_FORMATS";
const MATRIX_CLASSES_ENV: &str = "MARTY_ES256_MATRIX_CLASSES";
const MATRIX_ITEM_COUNTS_ENV: &str = "MARTY_ES256_MATRIX_ITEM_COUNTS";
const MATRIX_BATCH_SIZES_ENV: &str = "MARTY_ES256_MATRIX_BATCH_SIZES";
const LARGE_VALUE_BYTES: usize = 256 * 1024;
const MIXED_MEDIUM_BYTES: usize = 1024;
const MIXED_LARGE_BYTES: usize = 64 * 1024;
const MDOC_NAMESPACE: &str = "org.example.benchmark.payload";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixFormat {
    JwtVc,
    IetfSdJwt,
    W3cSdJwt,
    Mdoc,
}

impl MatrixFormat {
    pub const ALL: [Self; 4] = [Self::JwtVc, Self::IetfSdJwt, Self::W3cSdJwt, Self::Mdoc];

    pub const fn label(self) -> &'static str {
        match self {
            Self::JwtVc => "jwt_vc",
            Self::IetfSdJwt => "proof_bound_ietf_sd_jwt",
            Self::W3cSdJwt => "proof_bound_w3c_sd_jwt",
            Self::Mdoc => "mdoc",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "jwt_vc" => Some(Self::JwtVc),
            "proof_bound_ietf_sd_jwt" => Some(Self::IetfSdJwt),
            "proof_bound_w3c_sd_jwt" => Some(Self::W3cSdJwt),
            "mdoc" => Some(Self::Mdoc),
            _ => None,
        }
    }

    pub const fn is_sd_jwt(self) -> bool {
        matches!(self, Self::IetfSdJwt | Self::W3cSdJwt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadClass {
    SmallPrimitive,
    MediumNested,
    LargePortrait,
    MixedSize,
}

impl PayloadClass {
    pub const ALL: [Self; 4] = [
        Self::SmallPrimitive,
        Self::MediumNested,
        Self::LargePortrait,
        Self::MixedSize,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::SmallPrimitive => "small_primitive",
            Self::MediumNested => "medium_nested",
            Self::LargePortrait => "large_portrait",
            Self::MixedSize => "mixed_size",
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

#[derive(Debug, Eq, PartialEq)]
pub struct MatrixSelection {
    pub formats: Vec<MatrixFormat>,
    pub classes: Vec<PayloadClass>,
    pub item_counts: Vec<usize>,
    pub batch_sizes: Vec<usize>,
}

impl MatrixSelection {
    pub fn from_env() -> Self {
        Self {
            formats: parse_named_selector(
                MATRIX_FORMATS_ENV,
                &MatrixFormat::ALL,
                MatrixFormat::label,
                MatrixFormat::parse,
            ),
            classes: parse_named_selector(
                MATRIX_CLASSES_ENV,
                &PayloadClass::ALL,
                PayloadClass::label,
                PayloadClass::parse,
            ),
            item_counts: parse_numeric_selector(MATRIX_ITEM_COUNTS_ENV, &ITEM_COUNTS),
            batch_sizes: parse_numeric_selector(MATRIX_BATCH_SIZES_ENV, &MATRIX_BATCH_SIZES),
        }
    }
}

pub fn matrix_enabled() -> bool {
    std::env::var(MATRIX_ENABLE_ENV).is_ok_and(|value| value == "1")
}

fn selector_values(name: &str) -> Option<Vec<String>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must contain Unicode text"),
    };
    let values = value
        .split(',')
        .map(|value| {
            assert!(!value.is_empty(), "{name} contains an empty value");
            let value = value.trim();
            assert!(!value.is_empty(), "{name} contains an empty value");
            value
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(!values.is_empty(), "{name} must select at least one value");
    if values.iter().any(|value| value == "all") {
        assert_eq!(values, ["all"], "{name}=all cannot be combined with values");
        None
    } else {
        Some(values)
    }
}

fn parse_named_selector<T: Copy + Eq>(
    name: &str,
    allowed: &[T],
    label: impl Fn(T) -> &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Vec<T> {
    let Some(values) = selector_values(name) else {
        return allowed.to_vec();
    };
    let selected = values
        .iter()
        .map(|value| {
            parse(value).unwrap_or_else(|| {
                panic!(
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
        .collect::<Vec<_>>();
    assert_unique(name, &selected, |value| label(value).to_owned());
    selected
}

fn parse_numeric_selector(name: &str, allowed: &[usize]) -> Vec<usize> {
    let Some(values) = selector_values(name) else {
        return allowed.to_vec();
    };
    let selected = values
        .iter()
        .map(|value| {
            let parsed = value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} value '{value}' is not an integer"));
            assert_eq!(
                parsed.to_string(),
                *value,
                "{name} value '{value}' is not canonical"
            );
            assert!(
                allowed.contains(&parsed),
                "unsupported {name} value '{value}'; expected one of {}",
                allowed
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            parsed
        })
        .collect::<Vec<_>>();
    assert_unique(name, &selected, |value| value.to_string());
    selected
}

fn assert_unique<T: Copy + Eq>(name: &str, values: &[T], label: impl Fn(T) -> String) {
    for (ordinal, value) in values.iter().copied().enumerate() {
        assert!(
            !values[..ordinal].contains(&value),
            "{name} repeats '{}'",
            label(value)
        );
    }
}

fn claim_name(index: usize) -> String {
    format!("benchmark_claim_{index:04}")
}

fn repeated_ascii(length: usize, index: usize) -> String {
    let byte = b'A' + u8::try_from(index % 26).unwrap();
    String::from_utf8(vec![byte; length]).unwrap()
}

pub fn expected_payload_value(class: PayloadClass, index: usize) -> serde_json::Value {
    match class {
        PayloadClass::SmallPrimitive => match index % 3 {
            0 => serde_json::json!(index),
            1 => serde_json::json!(index.is_multiple_of(2)),
            _ => serde_json::json!(format!("value-{index:04}")),
        },
        PayloadClass::MediumNested => serde_json::json!({
            "group": index % 8,
            "metadata": {
                "enabled": index.is_multiple_of(2),
                "sequence": index,
                "label": format!("nested-{index:04}")
            },
            "values": [index, index + 1, index + 2, index + 3]
        }),
        PayloadClass::LargePortrait if index == 0 => serde_json::json!(format!(
            "data:application/octet-stream;base64,{}",
            repeated_ascii(LARGE_VALUE_BYTES, index)
        )),
        PayloadClass::LargePortrait => serde_json::json!(format!("value-{index:04}")),
        PayloadClass::MixedSize => match index % 4 {
            0 if index == 0 => serde_json::json!(repeated_ascii(MIXED_LARGE_BYTES, index)),
            0 => serde_json::json!(repeated_ascii(MIXED_MEDIUM_BYTES, index)),
            1 => serde_json::json!({
                "sequence": index,
                "flags": [true, false, index.is_multiple_of(2)]
            }),
            2 => serde_json::json!(index),
            _ => serde_json::json!(format!("mixed-{index:04}")),
        },
    }
}

pub fn matrix_claims(
    format: MatrixFormat,
    class: PayloadClass,
    item_count: usize,
    credential_ordinal: usize,
) -> CredentialClaims {
    assert!(ITEM_COUNTS.contains(&item_count));
    let claims = (0..item_count)
        .map(|index| (claim_name(index), expected_payload_value(class, index)))
        .collect::<HashMap<_, _>>();
    let selective_disclosure_claims = if format.is_sd_jwt() {
        (0..item_count).map(claim_name).collect()
    } else {
        vec![]
    };
    let credential_payload_format = match format {
        MatrixFormat::JwtVc => CredentialPayloadFormat::W3cVcdmV2JwtVc,
        MatrixFormat::IetfSdJwt => CredentialPayloadFormat::IetfSdJwt,
        MatrixFormat::W3cSdJwt => CredentialPayloadFormat::W3cVcdmV2SdJwt,
        MatrixFormat::Mdoc => CredentialPayloadFormat::default(),
    };

    CredentialClaims {
        subject_id: Some(format!("urn:example:benchmark-holder:{credential_ordinal}")),
        credential_type: match format {
            MatrixFormat::Mdoc => "org.example.benchmark.payload".into(),
            _ => "BenchmarkPayloadCredential".into(),
        },
        claims,
        expiration_seconds: Some(3_600),
        selective_disclosure_claims,
        mdoc_namespace: (format == MatrixFormat::Mdoc).then(|| MDOC_NAMESPACE.into()),
        mdoc_doctype: (format == MatrixFormat::Mdoc)
            .then(|| "org.example.benchmark.payload".into()),
        zk_predicate_claims: vec![],
        credential_payload_format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

pub fn expected_claim_names(item_count: usize) -> Vec<String> {
    (0..item_count).map(claim_name).collect()
}
