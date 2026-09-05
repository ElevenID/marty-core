use marty_python_adapters::{json_to_python, status_list};
use pyo3::exceptions::{PyIndexError, PyValueError};
use pyo3::prelude::*;

fn check_status_profile(register: fn(&Bound<'_, PyModule>) -> PyResult<()>, raw: bool) {
    Python::initialize();
    Python::attach(|py| {
        let parent = PyModule::new(py, "adapter_contract").unwrap();
        register(&parent).unwrap();
        let child = parent.getattr("status_list").unwrap();
        for name in ["TokenStatusList", "BitstringStatusList"] {
            let class = parent.getattr(name).unwrap();
            assert!(class.is(child.getattr(name).unwrap()));
            assert_eq!(class.hasattr("from_bytes").unwrap(), raw);
            let list = class.call1((8,)).unwrap();
            assert_eq!(
                list.call_method0("len")
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                8
            );
            list.call_method1("revoke", (0,)).unwrap();
            assert!(list
                .call_method1("is_revoked", (0,))
                .unwrap()
                .extract::<bool>()
                .unwrap());
            assert!(list
                .call_method1("get", (8,))
                .unwrap_err()
                .is_instance_of::<PyIndexError>(py));
            list.call_method1("reinstate", (0,)).unwrap();
            assert!(!list
                .call_method1("is_revoked", (0,))
                .unwrap()
                .extract::<bool>()
                .unwrap());
        }
        let token_class = parent.getattr("TokenStatusList").unwrap();
        let token = token_class.call1((2,)).unwrap();
        assert_eq!(
            token
                .call_method0("bits_per_status")
                .unwrap()
                .extract::<u8>()
                .unwrap(),
            8
        );
        assert!(token_class
            .call1((2, 3))
            .unwrap_err()
            .is_instance_of::<PyValueError>(py));
        let claim: String = parent
            .getattr("create_status_list_claim")
            .unwrap()
            .call1((&token,))
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&claim).unwrap()["bits"],
            8
        );
        let bits = parent
            .getattr("BitstringStatusList")
            .unwrap()
            .call1((marty_status::W3C_MIN_STATUS_LIST_BITS,))
            .unwrap();
        let subject: String = parent
            .getattr("create_bitstring_credential_subject")
            .unwrap()
            .call1((&bits, "urn:example:status"))
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&subject).unwrap()["statusPurpose"],
            "revocation"
        );
    });
}

#[test]
fn full_status_api_preserves_defaults_exceptions_and_aliases() {
    check_status_profile(status_list::full::register, true);
}

#[test]
fn compressed_status_api_preserves_its_smaller_surface() {
    check_status_profile(status_list::compressed::register, false);
}

#[test]
fn json_conversion_preserves_nested_values_and_integer_precision() {
    let value = serde_json::json!({
        "signed": i64::MIN, "unsigned": u64::MAX,
        "nested": [null, true, false, 1.25, "Prénom", {"empty": []}]
    });
    Python::initialize();
    Python::attach(|py| {
        let object = json_to_python(py, &value).unwrap();
        let encoded: String = PyModule::import(py, "json")
            .unwrap()
            .getattr("dumps")
            .unwrap()
            .call1((object,))
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            value
        );
    });
}
