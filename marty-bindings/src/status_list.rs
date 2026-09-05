//! Core Python status-list API, including raw-byte restoration.

pub use marty_python_adapters::status_list::full::register as register_status_list_bindings;

#[cfg(test)]
mod tests {
    use marty_python_adapters::status_list::full::*;

    #[test]
    fn binding_preserves_ietf_normative_vector() {
        let values = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let mut list = TokenStatusList::new(values.len(), 1).unwrap();
        for (index, value) in values.into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        assert_eq!(list.to_bytes(), vec![0xb9, 0xa3]);
        assert_eq!(list.to_base64url().unwrap(), "eNrbuRgAAhcBXQ");
    }

    #[test]
    fn binding_preserves_multibit_roundtrip() {
        let mut list = TokenStatusList::new(100, 2).unwrap();
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        let restored =
            TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 100, 2).unwrap();
        assert_eq!(restored.to_bytes()[0], 0b1110_0100);
    }

    #[test]
    fn binding_preserves_w3c_multibase_contract() {
        let mut list = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS).unwrap();
        list.revoke(0).unwrap();
        list.revoke(7).unwrap();
        assert_eq!(list.to_bytes()[0], 0b1000_0001);
        let encoded = list.to_base64url().unwrap();
        assert!(encoded.starts_with('u'));
        let restored = BitstringStatusList::from_base64url(&encoded, list.len()).unwrap();
        assert_eq!(restored.count_revoked(), 2);
    }

    #[test]
    fn binding_rejects_malformed_and_unreasonable_inputs() {
        assert!(TokenStatusList::from_bytes(vec![0], 2, 8).is_err());
        assert!(BitstringStatusList::from_bytes(vec![0], 9).is_err());
        assert!(TokenStatusList::from_compressed(vec![1, 2, 3], 100, 8).is_err());
        assert!(BitstringStatusList::from_base64url("not-multibase", 8).is_err());
        assert!(TokenStatusList::new(marty_status::MAX_STATUS_LIST_ENTRIES + 1, 8).is_err());
    }

    #[test]
    fn binding_restores_persisted_raw_bytes() {
        let mut token = TokenStatusList::from_bytes(vec![0, 7], 2, 8).unwrap();
        assert_eq!(token.get(1).unwrap(), 7);
        token.set(0, 3).unwrap();
        assert_eq!(token.to_bytes(), vec![3, 7]);

        let mut bitstring = BitstringStatusList::from_bytes(vec![0b1000_0000], 8).unwrap();
        assert!(bitstring.get(0).unwrap());
        bitstring.reinstate(0).unwrap();
        assert_eq!(bitstring.to_bytes(), vec![0]);
    }

    #[test]
    fn binding_subject_uses_canonical_privacy_floor() {
        let small = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS - 1).unwrap();
        assert!(
            create_bitstring_credential_subject(&small, "urn:example:list", "revocation").is_err()
        );
    }
}
