//! Public scalar/encoding contracts for the BBS integer compatibility boundary.
//! This contains no credential keys or signing operations.
use elliptic_curve_legacy::{
    bigint::U384,
    consts::U48,
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    },
    Curve, FieldBytesEncoding, ScalarPrimitive,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct PublicScalarCurve;
impl Curve for PublicScalarCurve {
    type FieldBytesSize = U48;
    type Uint = U384;
    const ORDER: U384 = U384::from_be_hex("0000000000000000000000000000000073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}
impl FieldBytesEncoding<PublicScalarCurve> for U384 {}

type Scalar = ScalarPrimitive<PublicScalarCurve>;

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
fn public_scalar_arithmetic_preserves_modulus_boundaries() {
    let one = Scalar::from(1u64);
    let two = Scalar::from(2u64);
    let minus_one = Scalar::new(PublicScalarCurve::ORDER.wrapping_sub(&U384::from(1u64))).unwrap();
    assert_eq!(minus_one + one, Scalar::ZERO);
    assert_eq!(minus_one + two, one);
    assert_eq!(one - two, minus_one);
    assert_eq!(-one, minus_one);
    assert_eq!(-(-two), two);
}

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
fn public_scalar_encoding_preserves_width_and_rejects_overflow() {
    let scalar = Scalar::from(1u64);
    let bytes = scalar.to_bytes();
    assert_eq!(bytes.len(), 48);
    assert_eq!(bytes[47], 1);
    assert!(bytes[..47].iter().all(|b| *b == 0));
    assert_eq!(Scalar::from_slice(&bytes).unwrap(), scalar);
    assert!(Scalar::from_slice(&bytes[..47]).is_err());
    assert!(!bool::from(Scalar::new(PublicScalarCurve::ORDER).is_some()));
    assert!(!bool::from(Scalar::new(U384::MAX).is_some()));
}

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
fn legacy_choices_preserve_selection_and_comparison() {
    let one = Scalar::from(1u64);
    let two = Scalar::from(2u64);
    assert_eq!(Scalar::conditional_select(&one, &two, Choice::from(0)), one);
    assert_eq!(Scalar::conditional_select(&one, &two, Choice::from(1)), two);
    assert!(bool::from(one.ct_lt(&two)));
    assert!(!bool::from(two.ct_lt(&one)));
    assert!(bool::from(two.ct_gt(&one)));
    assert!(!bool::from(one.ct_eq(&two)));
    assert!(bool::from(Scalar::ZERO.is_zero()));
    assert!(bool::from(one.is_odd()));
    assert!(bool::from(two.is_even()));
}

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
fn legacy_rng_adapter_preserves_a_seeded_public_scalar_stream() {
    // A fixed public test seed checks byte delegation and range, not entropy quality.
    let mut left = StdRng::seed_from_u64(1729);
    let mut right = StdRng::seed_from_u64(1729);
    for _ in 0..32 {
        let a = Scalar::random(&mut left);
        let b = Scalar::random(&mut right);
        assert_eq!(a, b);
        assert!(a.as_uint() < &PublicScalarCurve::ORDER);
        assert_eq!(Scalar::from_slice(&a.to_bytes()).unwrap(), a);
    }
}

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
fn bls_scalar_integer_encodings_are_canonical_on_every_target() {
    use bls12_381_plus::{Bls12381G1, Scalar as BlsScalar};
    use elliptic_curve_legacy::{
        bigint::{U256, U512},
        ops::Reduce,
    };
    let scalar = BlsScalar::from_raw_unchecked([1, 2, 3, 4]);
    let bytes = scalar.to_be_bytes();
    let u256 = U256::from(scalar);
    let u384 = U384::from(scalar);
    let u512 = U512::from(scalar);
    assert_eq!(u256.to_be_bytes().as_slice(), bytes);
    assert_eq!(&u384.to_be_bytes()[16..], bytes);
    assert_eq!(&u512.to_be_bytes()[32..], bytes);
    let primitive = ScalarPrimitive::<Bls12381G1>::from(scalar);
    assert_eq!(primitive.as_uint(), &u384);
    assert_eq!(BlsScalar::from(primitive), scalar);
    assert_eq!(BlsScalar::from(u384), scalar);
    assert_eq!(<BlsScalar as Reduce<U512>>::reduce(u512), scalar);
    assert_eq!(
        <BlsScalar as Reduce<U512>>::reduce(U512::from(1u64)),
        BlsScalar::from(1u64)
    );
}
