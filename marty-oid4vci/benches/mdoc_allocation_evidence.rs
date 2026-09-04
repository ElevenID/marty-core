//! Opt-in aggregate allocation evidence for public remote mdoc preparation.
//!
//! This is a native, harness-free evidence binary rather than a Criterion
//! benchmark. It counts successful sizes requested from Rust's `System` global
//! allocator only while a selected public preparation boundary is executing.

#[cfg(not(target_family = "wasm"))]
#[global_allocator]
static ALLOCATOR: native::CountingAllocator = native::CountingAllocator;

#[cfg(not(target_family = "wasm"))]
fn main() {
    native::run();
}

#[cfg(target_family = "wasm")]
fn main() {
    panic!("mdoc allocation evidence is native-only");
}

#[cfg(not(target_family = "wasm"))]
mod native {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        collections::{HashMap, HashSet},
        hint::black_box,
        process::Command,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use base64::Engine;
    use ciborium::Value as CborValue;
    use marty_oid4vci::{
        formats::mdoc::{assemble_mdoc, PreparedMdoc},
        remote_credential::{
            prepare_remote_mdoc, prepare_remote_mdoc_batch, RemoteMdocBatchItem, RemoteMdocRequest,
        },
        types::SignedCredential,
    };
    use sha2::{Digest, Sha256};

    const ENABLE_ENV: &str = "MARTY_MDOC_ALLOC_EVIDENCE";
    const CLASSES_ENV: &str = "MARTY_MDOC_MATRIX_CLASSES";
    const ITEM_COUNTS_ENV: &str = "MARTY_MDOC_MATRIX_ITEM_COUNTS";
    const BATCH_SIZES_ENV: &str = "MARTY_MDOC_MATRIX_BATCH_SIZES";
    const RUN_LABEL_ENV: &str = "MARTY_MDOC_ALLOC_EVIDENCE_RUN_LABEL";
    const RECORD_SCHEMA: &str = "mdoc_requested_allocation_v1";
    const CBOR_TAG_ENCODED_CBOR: u64 = 24;
    const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
    const NAMESPACE: &str = "org.iso.18013.5.1";
    const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
    const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
    const LARGE_PORTRAIT_BYTES: usize = 256 * 1024;
    const MIXED_MEDIUM_BYTES: usize = 1024;
    const MIXED_LARGE_BYTES: usize = 64 * 1024;

    static MEASUREMENT_ACTIVE: AtomicBool = AtomicBool::new(false);
    static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_REQUESTED_BYTES: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_REQUESTED_BYTES: AtomicUsize = AtomicUsize::new(0);
    static COUNTER_OVERFLOWED: AtomicBool = AtomicBool::new(false);

    pub struct CountingAllocator;

    // SAFETY: every operation is delegated to `System` with its original
    // pointer/layout contract. Successful calls additionally update lock-free
    // counters; the bookkeeping neither allocates nor touches returned memory.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the `GlobalAlloc::alloc` contract.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() && MEASUREMENT_ACTIVE.load(Ordering::SeqCst) {
                record(&ALLOC_CALLS, 1);
                record(&ALLOC_REQUESTED_BYTES, layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the `GlobalAlloc::alloc_zeroed` contract.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() && MEASUREMENT_ACTIVE.load(Ordering::SeqCst) {
                record(&ALLOC_CALLS, 1);
                record(&ALLOC_REQUESTED_BYTES, layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: the caller supplies the `GlobalAlloc::dealloc` contract.
            unsafe { System.dealloc(pointer, layout) };
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: the caller supplies the `GlobalAlloc::realloc` contract.
            let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
            if !new_pointer.is_null() && MEASUREMENT_ACTIVE.load(Ordering::SeqCst) {
                record(&REALLOC_CALLS, 1);
                record(&REALLOC_REQUESTED_BYTES, new_size);
            }
            new_pointer
        }
    }

    fn record(counter: &AtomicUsize, value: usize) {
        if counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(value)
            })
            .is_err()
        {
            COUNTER_OVERFLOWED.store(true, Ordering::Relaxed);
        }
    }

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
        fn from_env() -> Self {
            Self {
                classes: parse_named_selector(
                    CLASSES_ENV,
                    &PayloadClass::ALL,
                    PayloadClass::label,
                    PayloadClass::parse,
                ),
                item_counts: parse_numeric_selector(ITEM_COUNTS_ENV, &ITEM_COUNTS),
                batch_sizes: parse_numeric_selector(BATCH_SIZES_ENV, &BATCH_SIZES),
            }
        }

        fn case_count(&self) -> usize {
            self.classes.len() * self.item_counts.len() * (1 + 2 * self.batch_sizes.len())
        }
    }

    #[derive(Clone, Copy)]
    struct AllocationSnapshot {
        alloc_calls: usize,
        alloc_requested_bytes: usize,
        realloc_calls: usize,
        realloc_requested_bytes: usize,
    }

    struct ActiveMeasurement;

    impl Drop for ActiveMeasurement {
        fn drop(&mut self) {
            MEASUREMENT_ACTIVE.store(false, Ordering::SeqCst);
        }
    }

    pub fn run() {
        if !enabled() {
            println!("{RECORD_SCHEMA} record=disabled enable_with={ENABLE_ENV}=1");
            return;
        }
        require_release_profile();

        // Parse every selector before constructing any semantic fixture.
        let selection = Selection::from_env();
        let run_label = run_label();
        allocator_counter_preflight();
        preflight_selection(&selection);

        let (revision, workspace_clean) = git_metadata();
        let parallelism = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(0);
        let profile = if cfg!(debug_assertions) {
            "debug_assertions"
        } else {
            "release"
        };
        println!(
            "{RECORD_SCHEMA} record=metadata revision={revision} workspace_clean={workspace_clean} run_label={run_label} package=marty-oid4vci package_version={} target_arch={} target_os={} target_family={} pointer_width={} profile={profile} available_parallelism={parallelism} allocator=std_system counter_scope=process_global execution=single_threaded boundary=public_remote_mdoc_preparation fixture_schema=mdoc_payload_matrix_v1",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS,
            std::env::consts::FAMILY,
            usize::BITS,
        );
        println!(
            "{RECORD_SCHEMA} record=contract alloc_requested_bytes=successful_alloc_and_alloc_zeroed_sizes realloc_requested_new_bytes=successful_realloc_new_sizes deallocations=unmeasured rss=unmeasured retained_live=unmeasured peak=unmeasured"
        );
        println!(
            "{RECORD_SCHEMA} record=preflight status=passed cases={}",
            selection.case_count()
        );

        emit_selection(&selection);
    }

    fn enabled() -> bool {
        match std::env::var(ENABLE_ENV) {
            Ok(value) => {
                assert_eq!(value, "1", "{ENABLE_ENV}, when set, must equal exactly 1");
                true
            }
            Err(std::env::VarError::NotPresent) => false,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("{ENABLE_ENV} must contain Unicode text")
            }
        }
    }

    #[cfg(debug_assertions)]
    fn require_release_profile() {
        panic!("{ENABLE_ENV}=1 requires the release bench profile; use cargo bench");
    }

    #[cfg(not(debug_assertions))]
    fn require_release_profile() {}

    fn run_label() -> String {
        let value = match std::env::var(RUN_LABEL_ENV) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => "local".to_owned(),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("{RUN_LABEL_ENV} must contain Unicode text")
            }
        };
        assert!(
            !value.is_empty() && value.len() <= 64,
            "{RUN_LABEL_ENV} must contain 1 to 64 characters"
        );
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "{RUN_LABEL_ENV} may contain only ASCII letters, digits, '.', '_', and '-'"
        );
        value
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
                value.to_owned()
            })
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
                        "unsupported {name} value; expected one of {}",
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
                    .unwrap_or_else(|_| panic!("{name} value is not an integer"));
                assert_eq!(parsed.to_string(), *value, "{name} value is not canonical");
                assert!(
                    allowed.contains(&parsed),
                    "unsupported {name} value; expected one of {}",
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

    fn reset_counters() {
        assert!(
            !MEASUREMENT_ACTIVE.load(Ordering::SeqCst),
            "allocation measurements must not overlap"
        );
        ALLOC_CALLS.store(0, Ordering::Relaxed);
        ALLOC_REQUESTED_BYTES.store(0, Ordering::Relaxed);
        REALLOC_CALLS.store(0, Ordering::Relaxed);
        REALLOC_REQUESTED_BYTES.store(0, Ordering::Relaxed);
        COUNTER_OVERFLOWED.store(false, Ordering::Relaxed);
    }

    fn measure<T>(operation: impl FnOnce() -> T) -> (T, AllocationSnapshot) {
        reset_counters();
        assert!(
            MEASUREMENT_ACTIVE
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "allocation measurements must not overlap"
        );
        let active_measurement = ActiveMeasurement;
        let output = black_box(operation());
        drop(active_measurement);
        assert!(
            !COUNTER_OVERFLOWED.load(Ordering::Relaxed),
            "allocation evidence counters overflowed"
        );
        let snapshot = AllocationSnapshot {
            alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
            alloc_requested_bytes: ALLOC_REQUESTED_BYTES.load(Ordering::Relaxed),
            realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
            realloc_requested_bytes: REALLOC_REQUESTED_BYTES.load(Ordering::Relaxed),
        };
        (output, snapshot)
    }

    fn allocator_counter_preflight() {
        let initial_layout = Layout::from_size_align(8, 8).unwrap();
        let grown_layout = Layout::from_size_align(16, 8).unwrap();
        let (pointer, snapshot) = measure(|| {
            // SAFETY: the layouts are non-zero and valid; a successful realloc
            // receives the pointer and original layout returned by `alloc`.
            unsafe {
                let pointer = std::alloc::alloc(initial_layout);
                if pointer.is_null() {
                    std::alloc::handle_alloc_error(initial_layout);
                }
                let pointer = std::alloc::realloc(pointer, initial_layout, grown_layout.size());
                if pointer.is_null() {
                    std::alloc::handle_alloc_error(grown_layout);
                }
                pointer
            }
        });
        assert_eq!(snapshot.alloc_calls, 1);
        assert_eq!(snapshot.alloc_requested_bytes, initial_layout.size());
        assert_eq!(snapshot.realloc_calls, 1);
        assert_eq!(snapshot.realloc_requested_bytes, grown_layout.size());
        // SAFETY: `pointer` was returned by the successful realloc above and
        // has exactly `grown_layout`'s size and alignment.
        unsafe { std::alloc::dealloc(pointer, grown_layout) };
    }

    fn matrix_claim_name(index: usize) -> String {
        format!("benchmark_claim_{index:04}")
    }

    fn repeated_ascii(length: usize, index: usize) -> String {
        let byte = b'A' + u8::try_from(index % 26).expect("fixture alphabet index must fit u8");
        String::from_utf8(vec![byte; length]).expect("fixture bytes must be ASCII")
    }

    fn matrix_json_value(class: PayloadClass, index: usize) -> serde_json::Value {
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

    fn matrix_expected_cbor_value(class: PayloadClass, index: usize) -> CborValue {
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

    fn matrix_credential_id(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        credential_ordinal: usize,
    ) -> String {
        assert!(ITEM_COUNTS.contains(&item_count));
        assert!(batch_size == 0 || BATCH_SIZES.contains(&batch_size));
        assert!(credential_ordinal < batch_size.max(1));
        let tail = (class.code() << 40)
            | (u64::try_from(item_count).unwrap() << 24)
            | (u64::try_from(batch_size).unwrap() << 12)
            | u64::try_from(credential_ordinal).unwrap();
        format!(
            "urn:uuid:{:08x}-{item_count:04x}-4{batch_size:03x}-8{credential_ordinal:03x}-{tail:012x}",
            class.code()
        )
    }

    fn matrix_batch_id(
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

    fn matrix_request(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
        credential_ordinal: usize,
    ) -> RemoteMdocRequest {
        assert!(ITEM_COUNTS.contains(&item_count));
        let claims = (0..item_count)
            .map(|index| (matrix_claim_name(index), matrix_json_value(class, index)))
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
                "large portrait fixtures must contain exactly one 256-KiB value"
            );
        }

        RemoteMdocRequest {
            issuer_id: format!(
                "did:example:matrix-issuer:{}:{item_count}:{batch_size}:{credential_ordinal}",
                class.label()
            ),
            algorithm: "ES256".into(),
            credential_type: DOC_TYPE.into(),
            namespace: NAMESPACE.into(),
            claims,
            expiration_seconds: Some(365 * 86_400),
            credential_id: Some(matrix_credential_id(
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

    fn matrix_requests(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
    ) -> Vec<RemoteMdocRequest> {
        (0..batch_size)
            .map(|ordinal| matrix_request(class, item_count, batch_size, ordinal))
            .collect()
    }

    fn matrix_batch(
        class: PayloadClass,
        item_count: usize,
        batch_size: usize,
    ) -> Vec<RemoteMdocBatchItem> {
        matrix_requests(class, item_count, batch_size)
            .into_iter()
            .enumerate()
            .map(|(ordinal, request)| {
                RemoteMdocBatchItem::new(
                    matrix_batch_id(class, item_count, batch_size, ordinal),
                    request,
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

    fn matrix_claim_index(identifier: &str, item_count: usize) -> usize {
        let encoded = identifier
            .strip_prefix("benchmark_claim_")
            .unwrap_or_else(|| panic!("unexpected matrix claim identifier"));
        let index = encoded
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("matrix claim identifier must end in an integer"));
        assert_eq!(
            identifier,
            matrix_claim_name(index),
            "matrix claim identifier must be canonical"
        );
        assert!(index < item_count, "matrix claim index must be in range");
        index
    }

    fn assert_matrix_prepared(
        class: PayloadClass,
        item_count: usize,
        expected_credential_id: &str,
        prepared: PreparedMdoc,
    ) {
        use isomdl::definitions::IssuerSigned;

        assert_eq!(prepared.credential_id, expected_credential_id);
        let credential = assemble_mdoc(prepared, &[0xa5; 64])
            .expect("allocation evidence fixture must assemble");
        let SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } = credential
        else {
            panic!("allocation evidence fixture must produce mso_mdoc");
        };
        assert_eq!(credential_id, expected_credential_id);

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(issuer_signed_b64)
            .expect("allocation evidence IssuerSigned must be base64url");
        let issuer_signed: IssuerSigned =
            isomdl::cbor::from_slice(&bytes).expect("allocation evidence IssuerSigned must decode");
        let mso_bytes = issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .expect("allocation evidence issuerAuth payload must be present");
        let namespaces = issuer_signed
            .namespaces
            .as_ref()
            .expect("allocation evidence nameSpaces must be present");
        assert_eq!(namespaces.len(), 1, "fixtures have one namespace");
        let items = namespaces
            .get(NAMESPACE)
            .expect("allocation evidence namespace must be present");
        assert_eq!(items.len(), item_count, "fixtures contain no decoys");

        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) =
            isomdl::cbor::from_slice::<CborValue>(mso_bytes)
                .expect("allocation evidence MobileSecurityObjectBytes must decode")
        else {
            panic!("allocation evidence MobileSecurityObjectBytes must use tag 24");
        };
        let CborValue::Bytes(encoded_mso) = *encoded_mso else {
            panic!("allocation evidence MobileSecurityObjectBytes must wrap bytes");
        };
        let CborValue::Map(mso) = isomdl::cbor::from_slice::<CborValue>(&encoded_mso)
            .expect("allocation evidence MSO must decode")
        else {
            panic!("allocation evidence MSO must be a map");
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
            panic!("allocation evidence valueDigests must be a map");
        };
        assert_eq!(value_digests.len(), 1, "MSO has one namespace");
        let CborValue::Map(namespace_digests) = value_digests
            .iter()
            .find_map(|(key, value)| (key == &CborValue::Text(NAMESPACE.into())).then_some(value))
            .expect("allocation evidence namespace digests must be present")
        else {
            panic!("allocation evidence namespace valueDigests must be a map");
        };
        assert_eq!(
            namespace_digests.len(),
            item_count,
            "MSO contains no decoy digests"
        );

        let mut seen_indices = HashSet::with_capacity(item_count);
        for (expected_digest_id, (tagged_item, (digest_key, digest_value))) in
            items.iter().zip(namespace_digests).enumerate()
        {
            let item = tagged_item.as_ref();
            let digest_id = serde_json::to_value(item.digest_id)
                .expect("allocation evidence digest ID must serialize")
                .as_u64()
                .expect("allocation evidence digest ID must be unsigned");
            assert_eq!(digest_id, expected_digest_id as u64);
            assert_eq!(
                digest_key,
                &CborValue::Integer(digest_id.into()),
                "MSO digest order must match IssuerSignedItem order"
            );
            let CborValue::Bytes(expected_digest) = digest_value else {
                panic!("allocation evidence valueDigest must be bytes");
            };
            let encoded_wrapper = isomdl::cbor::to_vec(tagged_item)
                .expect("allocation evidence tag-24 item must encode");
            assert_eq!(
                Sha256::digest(encoded_wrapper).as_slice(),
                expected_digest,
                "MSO must commit to the complete tag-24 item"
            );

            let claim_index = matrix_claim_index(&item.element_identifier, item_count);
            assert!(
                seen_indices.insert(claim_index),
                "allocation evidence claim identifiers must be unique"
            );
            assert_eq!(
                item.element_value,
                matrix_expected_cbor_value(class, claim_index),
                "allocation evidence item must preserve its independent expected value"
            );
        }
        assert_eq!(seen_indices.len(), item_count);
    }

    fn assert_unique_request_ids(requests: &[RemoteMdocRequest]) {
        let mut credential_ids = HashSet::with_capacity(requests.len());
        let mut issuer_ids = HashSet::with_capacity(requests.len());
        for request in requests {
            assert!(
                credential_ids.insert(request.credential_id.as_deref().unwrap()),
                "allocation evidence credential identities must be unique"
            );
            assert!(
                issuer_ids.insert(request.issuer_id.as_str()),
                "allocation evidence issuer identities must be unique"
            );
        }
    }

    fn preflight_scalar(class: PayloadClass, item_count: usize) {
        let request = matrix_request(class, item_count, 0, 0);
        let credential_id = request.credential_id.clone().unwrap();
        let prepared = prepare_remote_mdoc(request)
            .unwrap_or_else(|_| panic!("allocation evidence scalar preflight must prepare"));
        assert_matrix_prepared(class, item_count, &credential_id, prepared);
    }

    fn preflight_sequential(class: PayloadClass, item_count: usize, batch_size: usize) {
        let requests = matrix_requests(class, item_count, batch_size);
        assert_unique_request_ids(&requests);
        for request in requests {
            let credential_id = request.credential_id.clone().unwrap();
            let prepared = prepare_remote_mdoc(request).unwrap_or_else(|_| {
                panic!("allocation evidence sequential preflight must prepare")
            });
            assert_matrix_prepared(class, item_count, &credential_id, prepared);
        }
    }

    fn preflight_batch(class: PayloadClass, item_count: usize, batch_size: usize) {
        let requests = matrix_requests(class, item_count, batch_size);
        assert_unique_request_ids(&requests);
        let expected = requests
            .iter()
            .enumerate()
            .map(|(ordinal, request)| {
                (
                    matrix_batch_id(class, item_count, batch_size, ordinal),
                    request.credential_id.clone().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut seen_batch_ids = HashSet::with_capacity(batch_size);
        let batch = requests
            .into_iter()
            .zip(&expected)
            .map(|(request, (batch_id, _))| {
                assert!(
                    seen_batch_ids.insert(*batch_id),
                    "allocation evidence routing identities must be unique"
                );
                RemoteMdocBatchItem::new(*batch_id, request)
            })
            .collect();
        let prepared = prepare_remote_mdoc_batch(batch)
            .unwrap_or_else(|_| panic!("allocation evidence batch preflight must prepare"));
        assert_eq!(prepared.len(), batch_size);
        for ((expected_batch_id, credential_id), prepared) in expected.into_iter().zip(prepared) {
            assert_eq!(
                prepared.batch_id(),
                expected_batch_id,
                "allocation evidence batch must preserve caller order and identity"
            );
            assert_matrix_prepared(
                class,
                item_count,
                &credential_id,
                prepared.into_prepared_mdoc(),
            );
        }
    }

    fn preflight_selection(selection: &Selection) {
        for &class in &selection.classes {
            for &item_count in &selection.item_counts {
                preflight_scalar(class, item_count);
                for &batch_size in &selection.batch_sizes {
                    preflight_sequential(class, item_count, batch_size);
                    preflight_batch(class, item_count, batch_size);
                }
            }
        }
    }

    fn emit_snapshot(
        route: &str,
        class: PayloadClass,
        item_count: usize,
        batch_size: Option<usize>,
        credential_count: usize,
        snapshot: AllocationSnapshot,
    ) {
        let batch_size = batch_size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "na".to_owned());
        println!(
            "{RECORD_SCHEMA} record=evidence route={route} class={} n={item_count} b={batch_size} credential_count={credential_count} alloc_calls={} alloc_requested_bytes={} realloc_calls={} realloc_requested_new_bytes={}",
            class.label(),
            snapshot.alloc_calls,
            snapshot.alloc_requested_bytes,
            snapshot.realloc_calls,
            snapshot.realloc_requested_bytes,
        );
    }

    fn measure_scalar(class: PayloadClass, item_count: usize) {
        let request = matrix_request(class, item_count, 0, 0);
        let credential_id = request.credential_id.clone().unwrap();
        let (prepared, snapshot) = measure(|| prepare_remote_mdoc(black_box(request)).ok());
        let prepared = prepared
            .unwrap_or_else(|| panic!("allocation evidence scalar measurement must prepare"));
        assert_matrix_prepared(class, item_count, &credential_id, black_box(prepared));
        emit_snapshot("scalar", class, item_count, None, 1, snapshot);
    }

    fn measure_sequential(class: PayloadClass, item_count: usize, batch_size: usize) {
        let requests = matrix_requests(class, item_count, batch_size);
        let (prepared, snapshot) = measure(|| {
            black_box(requests)
                .into_iter()
                .map(|request| prepare_remote_mdoc(black_box(request)))
                .collect::<Result<Vec<_>, _>>()
                .ok()
        });
        let prepared = prepared
            .unwrap_or_else(|| panic!("allocation evidence sequential measurement must prepare"));
        assert_eq!(prepared.len(), batch_size);
        for (ordinal, prepared) in black_box(prepared).into_iter().enumerate() {
            let credential_id = matrix_credential_id(class, item_count, batch_size, ordinal);
            assert_matrix_prepared(class, item_count, &credential_id, prepared);
        }
        emit_snapshot(
            "sequential",
            class,
            item_count,
            Some(batch_size),
            batch_size,
            snapshot,
        );
    }

    fn measure_batch(class: PayloadClass, item_count: usize, batch_size: usize) {
        let batch = matrix_batch(class, item_count, batch_size);
        let (prepared, snapshot) = measure(|| prepare_remote_mdoc_batch(black_box(batch)).ok());
        let prepared = prepared
            .unwrap_or_else(|| panic!("allocation evidence batch measurement must prepare"));
        assert_eq!(prepared.len(), batch_size);
        for (ordinal, prepared) in black_box(prepared).into_iter().enumerate() {
            assert_eq!(
                prepared.batch_id(),
                matrix_batch_id(class, item_count, batch_size, ordinal)
            );
            let credential_id = matrix_credential_id(class, item_count, batch_size, ordinal);
            assert_matrix_prepared(
                class,
                item_count,
                &credential_id,
                prepared.into_prepared_mdoc(),
            );
        }
        emit_snapshot(
            "batch",
            class,
            item_count,
            Some(batch_size),
            batch_size,
            snapshot,
        );
    }

    fn emit_selection(selection: &Selection) {
        for &class in &selection.classes {
            for &item_count in &selection.item_counts {
                measure_scalar(class, item_count);
                for &batch_size in &selection.batch_sizes {
                    measure_sequential(class, item_count, batch_size);
                    measure_batch(class, item_count, batch_size);
                }
            }
        }
    }

    fn git_metadata() -> (String, bool) {
        let revision = git_output(&["rev-parse", "--verify", "HEAD"])
            .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .unwrap_or_else(|| "unknown".to_owned());
        let workspace_clean = Command::new("git")
            .args([
                "-C",
                env!("CARGO_MANIFEST_DIR"),
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .is_some_and(|output| output.stdout.is_empty());
        (revision, workspace_clean)
    }

    fn git_output(arguments: &[&str]) -> Option<String> {
        let output = Command::new("git")
            .args(["-C", env!("CARGO_MANIFEST_DIR")])
            .args(arguments)
            .output()
            .ok()?;
        output.status.success().then(|| {
            String::from_utf8(output.stdout)
                .expect("git evidence metadata must be Unicode")
                .trim()
                .to_ascii_lowercase()
        })
    }
}
