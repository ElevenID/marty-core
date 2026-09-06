//! Deterministic inputs and an independent CBOR oracle for mdoc evidence.

use ciborium::Value as CborValue;

pub const LARGE_PORTRAIT_BYTES: usize = 256 * 1024;
const MIXED_MEDIUM_BYTES: usize = 1024;
const MIXED_LARGE_BYTES: usize = 64 * 1024;

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

    pub const fn code(self) -> u64 {
        match self {
            Self::SmallPrimitive => 1,
            Self::MediumNested => 2,
            Self::LargePortrait => 3,
            Self::MixedSize => 4,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "small_primitive" => Some(Self::SmallPrimitive),
            "medium_nested" => Some(Self::MediumNested),
            "large_portrait" => Some(Self::LargePortrait),
            "mixed_size" => Some(Self::MixedSize),
            _ => None,
        }
    }
}

pub fn repeated_ascii(length: usize, index: usize) -> String {
    let byte = b'A' + u8::try_from(index % 26).expect("fixture alphabet index must fit u8");
    String::from_utf8(vec![byte; length]).expect("fixture bytes must be ASCII")
}

pub fn json_value(class: PayloadClass, index: usize) -> serde_json::Value {
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
            0 if index == 0 => serde_json::Value::String(repeated_ascii(MIXED_LARGE_BYTES, index)),
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

pub fn cbor_integer(value: usize) -> CborValue {
    CborValue::Integer(
        u64::try_from(value)
            .expect("fixture integer must fit u64")
            .into(),
    )
}

pub fn expected_cbor_value(class: PayloadClass, index: usize) -> CborValue {
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
