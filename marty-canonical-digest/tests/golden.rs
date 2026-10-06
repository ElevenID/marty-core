use marty_canonical_digest::{canonical_digest, canonical_digest_json};

#[test]
fn frozen_json_digest_vectors_preserve_governance_bytes() {
    // Digests were independently calculated over the stated UTF-8 byte strings.
    // These pin the pre-extraction governance algorithm, not RFC 8785 behavior.
    let cases = [
        (
            r#"{ "b": 2, "a": 1 }"#,
            r#"{"a":1,"b":2}"#,
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        ),
        (
            r#"[{"z":1,"a":2}, true, null]"#,
            r#"[{"a":2,"z":1},true,null]"#,
            "ee91cde7d305e183b232e581de2b8d96bd1c0853f9d3cc8d9c24694e5341c4ee",
        ),
        (
            r#""\u00e9\uD83D\uDE00""#,
            "\"é😀\"",
            "5120b0dbdd5539f03b48389a6740c87aa497758ca96b3d69165453c9e01f3235",
        ),
        (
            r#"{"\u00e9":"\uD83D\uDE00"}"#,
            r#"{"é":"😀"}"#,
            "5b1d7df2c21dc54efccf82e1619e4bb36e2c98b777cccf238af48a4e11f36585",
        ),
        (
            r#"{"a":1,"a":2}"#,
            r#"{"a":2}"#,
            "7e8059f495589fcd981232cc11d00b00da3802c01d688fa1cf1f6bed6e5bb33c",
        ),
        (
            r#"{"z": -0.0, "n": 1.0}"#,
            r#"{"n":1.0,"z":-0.0}"#,
            "bf3496b87264b4217a51dc27b3a532960d13f9b6d18460cd3f0d1aeef1b30be9",
        ),
    ];
    for (input, canonical_bytes, sha256) in cases {
        let expected = format!("sha256:{sha256}");
        assert_eq!(canonical_digest_json(input).unwrap(), expected, "{input}");
        assert_eq!(canonical_digest_json(canonical_bytes).unwrap(), expected);
        let value = serde_json::from_str(canonical_bytes).unwrap();
        assert_eq!(canonical_digest(&value).unwrap(), expected);
    }
}

#[test]
fn invalid_json_retains_public_error() {
    for input in ["", "{", "{} {}", r#""\uD800""#, "NaN"] {
        assert_eq!(
            canonical_digest_json(input),
            Err("value is not canonical JSON".to_string()),
            "{input}"
        );
    }
}
