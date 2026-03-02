use crate::ZkPredicate;

/// All data needed to generate or verify a ZK proof for an mDoc claim.
///
/// Bundles the raw cryptographic material (MSO bytes + COSE signature)
/// together with the claim metadata, so callers don't have to track them
/// separately.
pub struct MdocZkInput {
    /// Raw MSO (Mobile Security Object) bytes — the COSE_Sign1 payload.
    pub mso_bytes: Vec<u8>,
    /// COSE signature over the MSO.
    pub signature: Vec<u8>,
    /// Name of the mDoc claim being proved (e.g. `"birth_date"`).
    pub claim_name: String,
    /// Plaintext value of the claim.  **Never transmitted** — only used
    /// locally to run the ZK circuit.
    pub claim_value: String,
}

impl MdocZkInput {
    pub fn new(
        mso_bytes: Vec<u8>,
        signature: Vec<u8>,
        claim_name: impl Into<String>,
        claim_value: impl Into<String>,
    ) -> Self {
        Self {
            mso_bytes,
            signature,
            claim_name: claim_name.into(),
            claim_value: claim_value.into(),
        }
    }

    /// Construct from raw COSE_Sign1 elements.
    ///
    /// The MSO is taken as the `payload` of the COSE_Sign1 structure
    /// (the ToBeSigned bytes that LibZK operates on).
    pub fn from_cose_sign1(
        _protected_header: &[u8],
        payload: &[u8],
        signature: &[u8],
        claim_name: impl Into<String>,
        claim_value: impl Into<String>,
    ) -> Self {
        Self {
            mso_bytes: payload.to_vec(),
            signature: signature.to_vec(),
            claim_name: claim_name.into(),
            claim_value: claim_value.into(),
        }
    }

    /// Verify that this input carries the claim required by the given predicate.
    pub fn claim_matches_predicate(&self, predicate: &ZkPredicate) -> bool {
        self.claim_name == predicate.required_claim()
    }
}
