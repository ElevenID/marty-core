//! Test fixtures module with embedded certificate data.
//!
//! Uses NIST PKITS test certificates from:
//! http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html

/// Trust Anchor Root Certificate (self-signed CA)
/// Subject: CN=Trust Anchor, O=Test Certificates 2011, C=US
pub const NIST_TRUST_ANCHOR_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/TrustAnchorRootCertificate.crt"
);

/// Good CA Certificate (signed by Trust Anchor)
/// Subject: CN=Good CA, O=Test Certificates 2011, C=US
pub const NIST_GOOD_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/GoodCACert.crt");

/// Valid Certificate Path Test 1 EE (end entity, signed by Good CA)
pub const NIST_VALID_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidCertificatePathTest1EE.crt"
);

/// Bad Signed CA Certificate (invalid signature)
pub const NIST_BAD_SIGNED_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/BadSignedCACert.crt");

/// Invalid CA Signature Test 2 EE
pub const NIST_INVALID_SIG_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidCASignatureTest2EE.crt"
);

/// DSA CA Certificate
pub const NIST_DSA_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/DSACACert.crt");

/// Valid DSA Signatures Test 4 EE
pub const NIST_VALID_DSA_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidDSASignaturesTest4EE.crt"
);

/// Certificate with expired notAfter
pub const NIST_BAD_NOT_AFTER_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/BadnotAfterDateCACert.crt"
);

/// Certificate with future notBefore
pub const NIST_BAD_NOT_BEFORE_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/BadnotBeforeDateCACert.crt"
);

// ============================================================================
// Extended NIST PKITS Certificate Collection
// ============================================================================

// -------------------- Name Chaining Tests --------------------

/// Invalid Name Chaining Test 1 EE - Name chain broken
pub const NIST_INVALID_NAME_CHAIN_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidNameChainingTest1EE.crt"
);

/// Invalid Name Chaining Order Test 2 EE
pub const NIST_INVALID_NAME_CHAIN_ORDER_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidNameChainingOrderTest2EE.crt"
);

/// Valid Name Chaining Whitespace Test 3 EE
pub const NIST_VALID_NAME_CHAIN_WHITESPACE_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidNameChainingWhitespaceTest3EE.crt"
);

/// Valid Name Chaining Whitespace Test 4 EE
pub const NIST_VALID_NAME_CHAIN_WHITESPACE_4_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidNameChainingWhitespaceTest4EE.crt"
);

/// Valid Name Chaining Capitalization Test 5 EE
pub const NIST_VALID_NAME_CHAIN_CAPS_5_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidNameChainingCapitalizationTest5EE.crt"
);

/// Valid Name UIDs Test 6 EE
pub const NIST_VALID_NAME_UIDS_6_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidNameUIDsTest6EE.crt"
);

// -------------------- Basic Constraints Tests --------------------

/// Basic Constraints Critical CA False Certificate
pub const NIST_BASIC_CONSTRAINTS_CA_FALSE_CRITICAL_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/basicConstraintsCriticalcAFalseCACert.crt"
);

/// Basic Constraints Not Critical Certificate
pub const NIST_BASIC_CONSTRAINTS_NOT_CRITICAL_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/basicConstraintsNotCriticalCACert.crt"
);

/// Missing Basic Constraints CA Certificate
pub const NIST_MISSING_BASIC_CONSTRAINTS_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/MissingbasicConstraintsCACert.crt"
);

/// Invalid Missing Basic Constraints Test 1 EE
pub const NIST_INVALID_MISSING_BASIC_CONSTRAINTS_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidMissingbasicConstraintsTest1EE.crt"
);

/// Invalid CA False Test 2 EE
pub const NIST_INVALID_CA_FALSE_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidcAFalseTest2EE.crt"
);

/// Invalid CA False Test 3 EE
pub const NIST_INVALID_CA_FALSE_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidcAFalseTest3EE.crt"
);

/// Valid Basic Constraints Not Critical Test 4 EE
pub const NIST_VALID_BASIC_CONSTRAINTS_4_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidbasicConstraintsNotCriticalTest4EE.crt"
);

// -------------------- Path Length Constraint Tests --------------------

/// Path Length Constraint 0 CA Certificate
pub const NIST_PATH_LEN_0_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/pathLenConstraint0CACert.crt"
);

/// Path Length Constraint 1 CA Certificate
pub const NIST_PATH_LEN_1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/pathLenConstraint1CACert.crt"
);

/// Path Length Constraint 6 CA Certificate
pub const NIST_PATH_LEN_6_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/pathLenConstraint6CACert.crt"
);

/// Invalid Path Length Constraint Test 5 EE
pub const NIST_INVALID_PATH_LEN_5_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidpathLenConstraintTest5EE.crt"
);

/// Invalid Path Length Constraint Test 6 EE
pub const NIST_INVALID_PATH_LEN_6_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidpathLenConstraintTest6EE.crt"
);

/// Valid Path Length Constraint Test 7 EE
pub const NIST_VALID_PATH_LEN_7_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidpathLenConstraintTest7EE.crt"
);

/// Valid Path Length Constraint Test 8 EE
pub const NIST_VALID_PATH_LEN_8_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidpathLenConstraintTest8EE.crt"
);

// -------------------- Key Usage Tests --------------------

/// Key Usage Critical keyCertSign False CA Certificate
pub const NIST_KEY_USAGE_CRITICAL_CERT_SIGN_FALSE_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/keyUsageCriticalkeyCertSignFalseCACert.crt"
);

/// Key Usage Critical cRLSign False CA Certificate
pub const NIST_KEY_USAGE_CRITICAL_CRL_SIGN_FALSE_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/keyUsageCriticalcRLSignFalseCACert.crt"
);

/// Key Usage Not Critical CA Certificate
pub const NIST_KEY_USAGE_NOT_CRITICAL_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/keyUsageNotCriticalCACert.crt"
);

/// Invalid Key Usage Critical keyCertSign False Test 1 EE
pub const NIST_INVALID_KEY_USAGE_CERT_SIGN_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt"
);

/// Invalid Key Usage Not Critical keyCertSign False Test 2 EE
pub const NIST_INVALID_KEY_USAGE_CERT_SIGN_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt"
);

/// Valid Key Usage Not Critical Test 3 EE
pub const NIST_VALID_KEY_USAGE_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidkeyUsageNotCriticalTest3EE.crt"
);

// -------------------- Certificate Policy Tests --------------------

/// No Policies CA Certificate
pub const NIST_NO_POLICIES_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/NoPoliciesCACert.crt");

/// Policies P12 CA Certificate
pub const NIST_POLICIES_P12_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/PoliciesP12CACert.crt");

/// Policies P123 CA Certificate
pub const NIST_POLICIES_P123_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/PoliciesP123CACert.crt"
);

/// anyPolicy CA Certificate
pub const NIST_ANY_POLICY_CA_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/anyPolicyCACert.crt");

/// All Certificates No Policies Test 2 EE
pub const NIST_ALL_CERTS_NO_POLICIES_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/AllCertificatesNoPoliciesTest2EE.crt"
);

/// All Certificates Same Policies Test 10 EE
pub const NIST_ALL_CERTS_SAME_POLICIES_10_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/AllCertificatesSamePoliciesTest10EE.crt"
);

// -------------------- Name Constraints Tests --------------------

/// Name Constraints DN1 CA Certificate
pub const NIST_NAME_CONSTRAINTS_DN1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/nameConstraintsDN1CACert.crt"
);

/// Name Constraints DN2 CA Certificate
pub const NIST_NAME_CONSTRAINTS_DN2_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/nameConstraintsDN2CACert.crt"
);

/// Name Constraints DNS1 CA Certificate
pub const NIST_NAME_CONSTRAINTS_DNS1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/nameConstraintsDNS1CACert.crt"
);

/// Name Constraints RFC822 CA1 Certificate
pub const NIST_NAME_CONSTRAINTS_RFC822_CA1_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/nameConstraintsRFC822CA1Cert.crt"
);

/// Name Constraints URI1 CA Certificate
pub const NIST_NAME_CONSTRAINTS_URI1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/nameConstraintsURI1CACert.crt"
);

/// Valid DN Name Constraints Test 1 EE
pub const NIST_VALID_DN_NAME_CONSTRAINTS_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidDNnameConstraintsTest1EE.crt"
);

/// Invalid DN Name Constraints Test 2 EE
pub const NIST_INVALID_DN_NAME_CONSTRAINTS_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidDNnameConstraintsTest2EE.crt"
);

/// Valid DNS Name Constraints Test 30 EE
pub const NIST_VALID_DNS_NAME_CONSTRAINTS_30_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidDNSnameConstraintsTest30EE.crt"
);

/// Invalid DNS Name Constraints Test 31 EE
pub const NIST_INVALID_DNS_NAME_CONSTRAINTS_31_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidDNSnameConstraintsTest31EE.crt"
);

// -------------------- Self-Issued Certificate Tests --------------------

/// Basic Self-Issued New Key CA Certificate
pub const NIST_BASIC_SELF_ISSUED_NEW_KEY_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/BasicSelfIssuedNewKeyCACert.crt"
);

/// Basic Self-Issued Old Key CA Certificate
pub const NIST_BASIC_SELF_ISSUED_OLD_KEY_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/BasicSelfIssuedOldKeyCACert.crt"
);

/// Basic Self-Issued CRL Signing Key CA Certificate
pub const NIST_BASIC_SELF_ISSUED_CRL_SIGNING_KEY_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/BasicSelfIssuedCRLSigningKeyCACert.crt"
);

/// Valid Basic Self-Issued Old With New Test 1 EE
pub const NIST_VALID_BASIC_SELF_ISSUED_OLD_WITH_NEW_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidBasicSelfIssuedOldWithNewTest1EE.crt"
);

/// Invalid Basic Self-Issued Old With New Test 2 EE
pub const NIST_INVALID_BASIC_SELF_ISSUED_OLD_WITH_NEW_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidBasicSelfIssuedOldWithNewTest2EE.crt"
);

/// Valid Basic Self-Issued New With Old Test 3 EE
pub const NIST_VALID_BASIC_SELF_ISSUED_NEW_WITH_OLD_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidBasicSelfIssuedNewWithOldTest3EE.crt"
);

// -------------------- Validity Period Tests --------------------

/// Invalid CA notBefore Date Test 1 EE
pub const NIST_INVALID_CA_NOT_BEFORE_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidCAnotBeforeDateTest1EE.crt"
);

/// Invalid EE notBefore Date Test 2 EE
pub const NIST_INVALID_EE_NOT_BEFORE_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidEEnotBeforeDateTest2EE.crt"
);

/// Valid Pre-2000 UTC notBefore Date Test 3 EE
pub const NIST_VALID_PRE2000_NOT_BEFORE_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/Validpre2000UTCnotBeforeDateTest3EE.crt"
);

/// Valid Generalized Time notBefore Date Test 4 EE
pub const NIST_VALID_GEN_TIME_NOT_BEFORE_4_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidGeneralizedTimenotBeforeDateTest4EE.crt"
);

/// Invalid CA notAfter Date Test 5 EE
pub const NIST_INVALID_CA_NOT_AFTER_5_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidCAnotAfterDateTest5EE.crt"
);

/// Invalid EE notAfter Date Test 6 EE
pub const NIST_INVALID_EE_NOT_AFTER_6_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidEEnotAfterDateTest6EE.crt"
);

/// Invalid Pre-2000 UTC EE notAfter Date Test 7 EE
pub const NIST_INVALID_PRE2000_NOT_AFTER_7_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/Invalidpre2000UTCEEnotAfterDateTest7EE.crt"
);

/// Valid Generalized Time notAfter Date Test 8 EE
pub const NIST_VALID_GEN_TIME_NOT_AFTER_8_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidGeneralizedTimenotAfterDateTest8EE.crt"
);

// -------------------- Distribution Point Tests --------------------

/// Distribution Point 1 CA Certificate
pub const NIST_DIST_POINT_1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/distributionPoint1CACert.crt"
);

/// Distribution Point 2 CA Certificate
pub const NIST_DIST_POINT_2_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/distributionPoint2CACert.crt"
);

/// Valid Distribution Point Test 1 EE
pub const NIST_VALID_DIST_POINT_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValiddistributionPointTest1EE.crt"
);

/// Invalid Distribution Point Test 2 EE
pub const NIST_INVALID_DIST_POINT_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvaliddistributionPointTest2EE.crt"
);

// -------------------- Delta CRL Tests --------------------

/// Delta CRL CA1 Certificate
pub const NIST_DELTA_CRL_CA1_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/deltaCRLCA1Cert.crt");

/// Delta CRL CA2 Certificate
pub const NIST_DELTA_CRL_CA2_DER: &[u8] =
    include_bytes!("../../../tests/cert_validator/fixtures/nist_pkits/certs/deltaCRLCA2Cert.crt");

/// Valid Delta CRL Test 2 EE
pub const NIST_VALID_DELTA_CRL_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValiddeltaCRLTest2EE.crt"
);

/// Invalid Delta CRL Test 3 EE
pub const NIST_INVALID_DELTA_CRL_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvaliddeltaCRLTest3EE.crt"
);

// -------------------- Inhibit Policy Mapping Tests --------------------

/// Inhibit Policy Mapping 0 CA Certificate
pub const NIST_INHIBIT_POLICY_MAPPING_0_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/inhibitPolicyMapping0CACert.crt"
);

/// Inhibit Policy Mapping 5 CA Certificate
pub const NIST_INHIBIT_POLICY_MAPPING_5_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/inhibitPolicyMapping5CACert.crt"
);

/// Invalid Inhibit Policy Mapping Test 1 EE
pub const NIST_INVALID_INHIBIT_POLICY_MAPPING_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidinhibitPolicyMappingTest1EE.crt"
);

/// Valid Inhibit Policy Mapping Test 2 EE
pub const NIST_VALID_INHIBIT_POLICY_MAPPING_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidinhibitPolicyMappingTest2EE.crt"
);

// -------------------- Inhibit Any-Policy Tests --------------------

/// Inhibit Any-Policy 0 CA Certificate
pub const NIST_INHIBIT_ANY_POLICY_0_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/inhibitAnyPolicy0CACert.crt"
);

/// Inhibit Any-Policy 1 CA Certificate
pub const NIST_INHIBIT_ANY_POLICY_1_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/inhibitAnyPolicy1CACert.crt"
);

/// Inhibit Any-Policy 5 CA Certificate
pub const NIST_INHIBIT_ANY_POLICY_5_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/inhibitAnyPolicy5CACert.crt"
);

/// Invalid Inhibit Any-Policy Test 1 EE
pub const NIST_INVALID_INHIBIT_ANY_POLICY_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidinhibitAnyPolicyTest1EE.crt"
);

/// Valid Inhibit Any-Policy Test 2 EE
pub const NIST_VALID_INHIBIT_ANY_POLICY_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidinhibitAnyPolicyTest2EE.crt"
);

// -------------------- Require Explicit Policy Tests --------------------

/// Require Explicit Policy 0 CA Certificate
pub const NIST_REQUIRE_EXPLICIT_POLICY_0_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/requireExplicitPolicy0CACert.crt"
);

/// Require Explicit Policy 2 CA Certificate
pub const NIST_REQUIRE_EXPLICIT_POLICY_2_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/requireExplicitPolicy2CACert.crt"
);

/// Valid Require Explicit Policy Test 1 EE
pub const NIST_VALID_REQUIRE_EXPLICIT_POLICY_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidrequireExplicitPolicyTest1EE.crt"
);

/// Valid Require Explicit Policy Test 2 EE
pub const NIST_VALID_REQUIRE_EXPLICIT_POLICY_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidrequireExplicitPolicyTest2EE.crt"
);

/// Invalid Require Explicit Policy Test 3 EE
pub const NIST_INVALID_REQUIRE_EXPLICIT_POLICY_3_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidrequireExplicitPolicyTest3EE.crt"
);

// -------------------- Encoding Tests (UTF-8, Generalized Time, etc.) --------------------

/// UTF-8 String Encoded Names CA Certificate
pub const NIST_UTF8_ENCODED_NAMES_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UTF8StringEncodedNamesCACert.crt"
);

/// UTF-8 String Case Insensitive Match CA Certificate
pub const NIST_UTF8_CASE_INSENSITIVE_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UTF8StringCaseInsensitiveMatchCACert.crt"
);

/// Rollover from Printable String to UTF-8 String CA Certificate
pub const NIST_ROLLOVER_PRINTABLE_UTF8_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/RolloverfromPrintableStringtoUTF8StringCACert.crt"
);

/// Valid UTF-8 String Encoded Names Test 9 EE
pub const NIST_VALID_UTF8_ENCODED_9_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidUTF8StringEncodedNamesTest9EE.crt"
);

/// Valid Rollover from Printable String to UTF-8 String Test 10 EE
pub const NIST_VALID_ROLLOVER_UTF8_10_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt"
);

/// Valid UTF-8 String Case Insensitive Match Test 11 EE
pub const NIST_VALID_UTF8_CASE_INSENSITIVE_11_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidUTF8StringCaseInsensitiveMatchTest11EE.crt"
);

/// Generalized Time CRL next Update CA Certificate
pub const NIST_GEN_TIME_CRL_NEXT_UPDATE_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/GeneralizedTimeCRLnextUpdateCACert.crt"
);

/// Valid Generalized Time CRL next Update Test 13 EE
pub const NIST_VALID_GEN_TIME_CRL_13_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidGeneralizedTimeCRLnextUpdateTest13EE.crt"
);

// -------------------- Serial Number Tests --------------------

/// Negative Serial Number CA Certificate
pub const NIST_NEGATIVE_SERIAL_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/NegativeSerialNumberCACert.crt"
);

/// Long Serial Number CA Certificate
pub const NIST_LONG_SERIAL_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/LongSerialNumberCACert.crt"
);

/// Valid Negative Serial Number Test 14 EE
pub const NIST_VALID_NEGATIVE_SERIAL_14_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidNegativeSerialNumberTest14EE.crt"
);

/// Invalid Negative Serial Number Test 15 EE
pub const NIST_INVALID_NEGATIVE_SERIAL_15_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidNegativeSerialNumberTest15EE.crt"
);

/// Valid Long Serial Number Test 16 EE
pub const NIST_VALID_LONG_SERIAL_16_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidLongSerialNumberTest16EE.crt"
);

/// Valid Long Serial Number Test 17 EE
pub const NIST_VALID_LONG_SERIAL_17_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidLongSerialNumberTest17EE.crt"
);

/// Invalid Long Serial Number Test 18 EE
pub const NIST_INVALID_LONG_SERIAL_18_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidLongSerialNumberTest18EE.crt"
);

// -------------------- Separate Certificate and CRL Keys Tests --------------------

/// Separate Certificate and CRL Keys Certificate Signing CA Certificate
pub const NIST_SEPARATE_CERT_CRL_KEYS_CERT_SIGNING_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/SeparateCertificateandCRLKeysCertificateSigningCACert.crt"
);

/// Separate Certificate and CRL Keys CRL Signing Certificate
pub const NIST_SEPARATE_CERT_CRL_KEYS_CRL_SIGNING_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/SeparateCertificateandCRLKeysCRLSigningCert.crt"
);

/// Valid Separate Certificate and CRL Keys Test 19 EE
pub const NIST_VALID_SEPARATE_CERT_CRL_KEYS_19_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidSeparateCertificateandCRLKeysTest19EE.crt"
);

/// Invalid Separate Certificate and CRL Keys Test 20 EE
pub const NIST_INVALID_SEPARATE_CERT_CRL_KEYS_20_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidSeparateCertificateandCRLKeysTest20EE.crt"
);

// -------------------- RFC 3280 Attribute Types Tests --------------------

/// RFC 3280 Mandatory Attribute Types CA Certificate
pub const NIST_RFC3280_MANDATORY_ATTR_TYPES_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/RFC3280MandatoryAttributeTypesCACert.crt"
);

/// RFC 3280 Optional Attribute Types CA Certificate
pub const NIST_RFC3280_OPTIONAL_ATTR_TYPES_CA_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/RFC3280OptionalAttributeTypesCACert.crt"
);

/// Valid RFC 3280 Mandatory Attribute Types Test 7 EE
pub const NIST_VALID_RFC3280_MANDATORY_7_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidRFC3280MandatoryAttributeTypesTest7EE.crt"
);

/// Valid RFC 3280 Optional Attribute Types Test 8 EE
pub const NIST_VALID_RFC3280_OPTIONAL_8_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidRFC3280OptionalAttributeTypesTest8EE.crt"
);

// -------------------- Unknown Critical Extension Tests --------------------

/// Valid Unknown Not Critical Certificate Extension Test 1 EE
pub const NIST_VALID_UNKNOWN_EXT_1_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/ValidUnknownNotCriticalCertificateExtensionTest1EE.crt"
);

/// Invalid Unknown Critical Certificate Extension Test 2 EE
pub const NIST_INVALID_UNKNOWN_EXT_2_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/InvalidUnknownCriticalCertificateExtensionTest2EE.crt"
);

// -------------------- User Notice Qualifier Tests --------------------

/// User Notice Qualifier Test 15 EE
pub const NIST_USER_NOTICE_15_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UserNoticeQualifierTest15EE.crt"
);

/// User Notice Qualifier Test 16 EE
pub const NIST_USER_NOTICE_16_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UserNoticeQualifierTest16EE.crt"
);

/// User Notice Qualifier Test 17 EE
pub const NIST_USER_NOTICE_17_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UserNoticeQualifierTest17EE.crt"
);

/// User Notice Qualifier Test 18 EE
pub const NIST_USER_NOTICE_18_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UserNoticeQualifierTest18EE.crt"
);

/// User Notice Qualifier Test 19 EE
pub const NIST_USER_NOTICE_19_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/UserNoticeQualifierTest19EE.crt"
);

/// CPS Pointer Qualifier Test 20 EE
pub const NIST_CPS_POINTER_20_EE_DER: &[u8] = include_bytes!(
    "../../../tests/cert_validator/fixtures/nist_pkits/certs/CPSPointerQualifierTest20EE.crt"
);

// ============================================================================
// Test Data Helper Functions
// ============================================================================

/// Get a map of all NIST PKITS test certificates for batch testing
pub fn all_nist_pkits_certs() -> Vec<(&'static str, &'static [u8])> {
    vec![
        // Core certificates
        ("TrustAnchorRootCertificate", NIST_TRUST_ANCHOR_DER),
        ("GoodCACert", NIST_GOOD_CA_DER),
        ("ValidCertificatePathTest1EE", NIST_VALID_EE_DER),
        ("BadSignedCACert", NIST_BAD_SIGNED_CA_DER),
        ("InvalidCASignatureTest2EE", NIST_INVALID_SIG_EE_DER),
        ("DSACACert", NIST_DSA_CA_DER),
        ("ValidDSASignaturesTest4EE", NIST_VALID_DSA_EE_DER),
        ("BadnotAfterDateCACert", NIST_BAD_NOT_AFTER_CA_DER),
        ("BadnotBeforeDateCACert", NIST_BAD_NOT_BEFORE_CA_DER),
        // Name Chaining
        (
            "InvalidNameChainingTest1EE",
            NIST_INVALID_NAME_CHAIN_1_EE_DER,
        ),
        (
            "InvalidNameChainingOrderTest2EE",
            NIST_INVALID_NAME_CHAIN_ORDER_2_EE_DER,
        ),
        (
            "ValidNameChainingWhitespaceTest3EE",
            NIST_VALID_NAME_CHAIN_WHITESPACE_3_EE_DER,
        ),
        (
            "ValidNameChainingWhitespaceTest4EE",
            NIST_VALID_NAME_CHAIN_WHITESPACE_4_EE_DER,
        ),
        (
            "ValidNameChainingCapitalizationTest5EE",
            NIST_VALID_NAME_CHAIN_CAPS_5_EE_DER,
        ),
        ("ValidNameUIDsTest6EE", NIST_VALID_NAME_UIDS_6_EE_DER),
        // Basic Constraints
        (
            "basicConstraintsCriticalcAFalseCACert",
            NIST_BASIC_CONSTRAINTS_CA_FALSE_CRITICAL_DER,
        ),
        (
            "basicConstraintsNotCriticalCACert",
            NIST_BASIC_CONSTRAINTS_NOT_CRITICAL_DER,
        ),
        (
            "MissingbasicConstraintsCACert",
            NIST_MISSING_BASIC_CONSTRAINTS_CA_DER,
        ),
        (
            "InvalidMissingbasicConstraintsTest1EE",
            NIST_INVALID_MISSING_BASIC_CONSTRAINTS_1_EE_DER,
        ),
        ("InvalidcAFalseTest2EE", NIST_INVALID_CA_FALSE_2_EE_DER),
        ("InvalidcAFalseTest3EE", NIST_INVALID_CA_FALSE_3_EE_DER),
        (
            "ValidbasicConstraintsNotCriticalTest4EE",
            NIST_VALID_BASIC_CONSTRAINTS_4_EE_DER,
        ),
        // Path Length Constraints
        ("pathLenConstraint0CACert", NIST_PATH_LEN_0_CA_DER),
        ("pathLenConstraint1CACert", NIST_PATH_LEN_1_CA_DER),
        ("pathLenConstraint6CACert", NIST_PATH_LEN_6_CA_DER),
        (
            "InvalidpathLenConstraintTest5EE",
            NIST_INVALID_PATH_LEN_5_EE_DER,
        ),
        (
            "InvalidpathLenConstraintTest6EE",
            NIST_INVALID_PATH_LEN_6_EE_DER,
        ),
        (
            "ValidpathLenConstraintTest7EE",
            NIST_VALID_PATH_LEN_7_EE_DER,
        ),
        (
            "ValidpathLenConstraintTest8EE",
            NIST_VALID_PATH_LEN_8_EE_DER,
        ),
        // Key Usage
        (
            "keyUsageCriticalkeyCertSignFalseCACert",
            NIST_KEY_USAGE_CRITICAL_CERT_SIGN_FALSE_CA_DER,
        ),
        (
            "keyUsageCriticalcRLSignFalseCACert",
            NIST_KEY_USAGE_CRITICAL_CRL_SIGN_FALSE_CA_DER,
        ),
        (
            "keyUsageNotCriticalCACert",
            NIST_KEY_USAGE_NOT_CRITICAL_CA_DER,
        ),
        (
            "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE",
            NIST_INVALID_KEY_USAGE_CERT_SIGN_1_EE_DER,
        ),
        (
            "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE",
            NIST_INVALID_KEY_USAGE_CERT_SIGN_2_EE_DER,
        ),
        (
            "ValidkeyUsageNotCriticalTest3EE",
            NIST_VALID_KEY_USAGE_3_EE_DER,
        ),
        // Certificate Policies
        ("NoPoliciesCACert", NIST_NO_POLICIES_CA_DER),
        ("PoliciesP12CACert", NIST_POLICIES_P12_CA_DER),
        ("PoliciesP123CACert", NIST_POLICIES_P123_CA_DER),
        ("anyPolicyCACert", NIST_ANY_POLICY_CA_DER),
        (
            "AllCertificatesNoPoliciesTest2EE",
            NIST_ALL_CERTS_NO_POLICIES_2_EE_DER,
        ),
        (
            "AllCertificatesSamePoliciesTest10EE",
            NIST_ALL_CERTS_SAME_POLICIES_10_EE_DER,
        ),
        // Name Constraints
        ("nameConstraintsDN1CACert", NIST_NAME_CONSTRAINTS_DN1_CA_DER),
        ("nameConstraintsDN2CACert", NIST_NAME_CONSTRAINTS_DN2_CA_DER),
        (
            "nameConstraintsDNS1CACert",
            NIST_NAME_CONSTRAINTS_DNS1_CA_DER,
        ),
        (
            "nameConstraintsRFC822CA1Cert",
            NIST_NAME_CONSTRAINTS_RFC822_CA1_DER,
        ),
        (
            "nameConstraintsURI1CACert",
            NIST_NAME_CONSTRAINTS_URI1_CA_DER,
        ),
        (
            "ValidDNnameConstraintsTest1EE",
            NIST_VALID_DN_NAME_CONSTRAINTS_1_EE_DER,
        ),
        (
            "InvalidDNnameConstraintsTest2EE",
            NIST_INVALID_DN_NAME_CONSTRAINTS_2_EE_DER,
        ),
        (
            "ValidDNSnameConstraintsTest30EE",
            NIST_VALID_DNS_NAME_CONSTRAINTS_30_EE_DER,
        ),
        (
            "InvalidDNSnameConstraintsTest31EE",
            NIST_INVALID_DNS_NAME_CONSTRAINTS_31_EE_DER,
        ),
        // Self-Issued
        (
            "BasicSelfIssuedNewKeyCACert",
            NIST_BASIC_SELF_ISSUED_NEW_KEY_CA_DER,
        ),
        (
            "BasicSelfIssuedOldKeyCACert",
            NIST_BASIC_SELF_ISSUED_OLD_KEY_CA_DER,
        ),
        (
            "BasicSelfIssuedCRLSigningKeyCACert",
            NIST_BASIC_SELF_ISSUED_CRL_SIGNING_KEY_CA_DER,
        ),
        (
            "ValidBasicSelfIssuedOldWithNewTest1EE",
            NIST_VALID_BASIC_SELF_ISSUED_OLD_WITH_NEW_1_EE_DER,
        ),
        (
            "InvalidBasicSelfIssuedOldWithNewTest2EE",
            NIST_INVALID_BASIC_SELF_ISSUED_OLD_WITH_NEW_2_EE_DER,
        ),
        (
            "ValidBasicSelfIssuedNewWithOldTest3EE",
            NIST_VALID_BASIC_SELF_ISSUED_NEW_WITH_OLD_3_EE_DER,
        ),
        // Validity Period
        (
            "InvalidCAnotBeforeDateTest1EE",
            NIST_INVALID_CA_NOT_BEFORE_1_EE_DER,
        ),
        (
            "InvalidEEnotBeforeDateTest2EE",
            NIST_INVALID_EE_NOT_BEFORE_2_EE_DER,
        ),
        (
            "Validpre2000UTCnotBeforeDateTest3EE",
            NIST_VALID_PRE2000_NOT_BEFORE_3_EE_DER,
        ),
        (
            "ValidGeneralizedTimenotBeforeDateTest4EE",
            NIST_VALID_GEN_TIME_NOT_BEFORE_4_EE_DER,
        ),
        (
            "InvalidCAnotAfterDateTest5EE",
            NIST_INVALID_CA_NOT_AFTER_5_EE_DER,
        ),
        (
            "InvalidEEnotAfterDateTest6EE",
            NIST_INVALID_EE_NOT_AFTER_6_EE_DER,
        ),
        (
            "Invalidpre2000UTCEEnotAfterDateTest7EE",
            NIST_INVALID_PRE2000_NOT_AFTER_7_EE_DER,
        ),
        (
            "ValidGeneralizedTimenotAfterDateTest8EE",
            NIST_VALID_GEN_TIME_NOT_AFTER_8_EE_DER,
        ),
        // Distribution Points
        ("distributionPoint1CACert", NIST_DIST_POINT_1_CA_DER),
        ("distributionPoint2CACert", NIST_DIST_POINT_2_CA_DER),
        (
            "ValiddistributionPointTest1EE",
            NIST_VALID_DIST_POINT_1_EE_DER,
        ),
        (
            "InvaliddistributionPointTest2EE",
            NIST_INVALID_DIST_POINT_2_EE_DER,
        ),
        // Delta CRL
        ("deltaCRLCA1Cert", NIST_DELTA_CRL_CA1_DER),
        ("deltaCRLCA2Cert", NIST_DELTA_CRL_CA2_DER),
        ("ValiddeltaCRLTest2EE", NIST_VALID_DELTA_CRL_2_EE_DER),
        ("InvaliddeltaCRLTest3EE", NIST_INVALID_DELTA_CRL_3_EE_DER),
        // Inhibit Policy Mapping
        (
            "inhibitPolicyMapping0CACert",
            NIST_INHIBIT_POLICY_MAPPING_0_CA_DER,
        ),
        (
            "inhibitPolicyMapping5CACert",
            NIST_INHIBIT_POLICY_MAPPING_5_CA_DER,
        ),
        (
            "InvalidinhibitPolicyMappingTest1EE",
            NIST_INVALID_INHIBIT_POLICY_MAPPING_1_EE_DER,
        ),
        (
            "ValidinhibitPolicyMappingTest2EE",
            NIST_VALID_INHIBIT_POLICY_MAPPING_2_EE_DER,
        ),
        // Inhibit Any-Policy
        ("inhibitAnyPolicy0CACert", NIST_INHIBIT_ANY_POLICY_0_CA_DER),
        ("inhibitAnyPolicy1CACert", NIST_INHIBIT_ANY_POLICY_1_CA_DER),
        ("inhibitAnyPolicy5CACert", NIST_INHIBIT_ANY_POLICY_5_CA_DER),
        (
            "InvalidinhibitAnyPolicyTest1EE",
            NIST_INVALID_INHIBIT_ANY_POLICY_1_EE_DER,
        ),
        (
            "ValidinhibitAnyPolicyTest2EE",
            NIST_VALID_INHIBIT_ANY_POLICY_2_EE_DER,
        ),
        // Require Explicit Policy
        (
            "requireExplicitPolicy0CACert",
            NIST_REQUIRE_EXPLICIT_POLICY_0_CA_DER,
        ),
        (
            "requireExplicitPolicy2CACert",
            NIST_REQUIRE_EXPLICIT_POLICY_2_CA_DER,
        ),
        (
            "ValidrequireExplicitPolicyTest1EE",
            NIST_VALID_REQUIRE_EXPLICIT_POLICY_1_EE_DER,
        ),
        (
            "ValidrequireExplicitPolicyTest2EE",
            NIST_VALID_REQUIRE_EXPLICIT_POLICY_2_EE_DER,
        ),
        (
            "InvalidrequireExplicitPolicyTest3EE",
            NIST_INVALID_REQUIRE_EXPLICIT_POLICY_3_EE_DER,
        ),
        // Encoding Tests
        (
            "UTF8StringEncodedNamesCACert",
            NIST_UTF8_ENCODED_NAMES_CA_DER,
        ),
        (
            "UTF8StringCaseInsensitiveMatchCACert",
            NIST_UTF8_CASE_INSENSITIVE_CA_DER,
        ),
        (
            "RolloverfromPrintableStringtoUTF8StringCACert",
            NIST_ROLLOVER_PRINTABLE_UTF8_CA_DER,
        ),
        (
            "ValidUTF8StringEncodedNamesTest9EE",
            NIST_VALID_UTF8_ENCODED_9_EE_DER,
        ),
        (
            "ValidRolloverfromPrintableStringtoUTF8StringTest10EE",
            NIST_VALID_ROLLOVER_UTF8_10_EE_DER,
        ),
        (
            "ValidUTF8StringCaseInsensitiveMatchTest11EE",
            NIST_VALID_UTF8_CASE_INSENSITIVE_11_EE_DER,
        ),
        (
            "GeneralizedTimeCRLnextUpdateCACert",
            NIST_GEN_TIME_CRL_NEXT_UPDATE_CA_DER,
        ),
        (
            "ValidGeneralizedTimeCRLnextUpdateTest13EE",
            NIST_VALID_GEN_TIME_CRL_13_EE_DER,
        ),
        // Serial Number Tests
        ("NegativeSerialNumberCACert", NIST_NEGATIVE_SERIAL_CA_DER),
        ("LongSerialNumberCACert", NIST_LONG_SERIAL_CA_DER),
        (
            "ValidNegativeSerialNumberTest14EE",
            NIST_VALID_NEGATIVE_SERIAL_14_EE_DER,
        ),
        (
            "InvalidNegativeSerialNumberTest15EE",
            NIST_INVALID_NEGATIVE_SERIAL_15_EE_DER,
        ),
        (
            "ValidLongSerialNumberTest16EE",
            NIST_VALID_LONG_SERIAL_16_EE_DER,
        ),
        (
            "ValidLongSerialNumberTest17EE",
            NIST_VALID_LONG_SERIAL_17_EE_DER,
        ),
        (
            "InvalidLongSerialNumberTest18EE",
            NIST_INVALID_LONG_SERIAL_18_EE_DER,
        ),
        // Separate Certificate and CRL Keys
        (
            "SeparateCertificateandCRLKeysCertificateSigningCACert",
            NIST_SEPARATE_CERT_CRL_KEYS_CERT_SIGNING_CA_DER,
        ),
        (
            "SeparateCertificateandCRLKeysCRLSigningCert",
            NIST_SEPARATE_CERT_CRL_KEYS_CRL_SIGNING_DER,
        ),
        (
            "ValidSeparateCertificateandCRLKeysTest19EE",
            NIST_VALID_SEPARATE_CERT_CRL_KEYS_19_EE_DER,
        ),
        (
            "InvalidSeparateCertificateandCRLKeysTest20EE",
            NIST_INVALID_SEPARATE_CERT_CRL_KEYS_20_EE_DER,
        ),
        // RFC 3280 Attribute Types
        (
            "RFC3280MandatoryAttributeTypesCACert",
            NIST_RFC3280_MANDATORY_ATTR_TYPES_CA_DER,
        ),
        (
            "RFC3280OptionalAttributeTypesCACert",
            NIST_RFC3280_OPTIONAL_ATTR_TYPES_CA_DER,
        ),
        (
            "ValidRFC3280MandatoryAttributeTypesTest7EE",
            NIST_VALID_RFC3280_MANDATORY_7_EE_DER,
        ),
        (
            "ValidRFC3280OptionalAttributeTypesTest8EE",
            NIST_VALID_RFC3280_OPTIONAL_8_EE_DER,
        ),
        // Unknown Critical Extension
        (
            "ValidUnknownNotCriticalCertificateExtensionTest1EE",
            NIST_VALID_UNKNOWN_EXT_1_EE_DER,
        ),
        (
            "InvalidUnknownCriticalCertificateExtensionTest2EE",
            NIST_INVALID_UNKNOWN_EXT_2_EE_DER,
        ),
        // User Notice
        ("UserNoticeQualifierTest15EE", NIST_USER_NOTICE_15_EE_DER),
        ("UserNoticeQualifierTest16EE", NIST_USER_NOTICE_16_EE_DER),
        ("UserNoticeQualifierTest17EE", NIST_USER_NOTICE_17_EE_DER),
        ("UserNoticeQualifierTest18EE", NIST_USER_NOTICE_18_EE_DER),
        ("UserNoticeQualifierTest19EE", NIST_USER_NOTICE_19_EE_DER),
        ("CPSPointerQualifierTest20EE", NIST_CPS_POINTER_20_EE_DER),
    ]
}
pub const TEST_SELF_SIGNED_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRl
c3RDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BlRlc3RDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKJ8vk8u6QHVL6gVGMOy
VU0E0Ep1M8GQaOVvMbJXuZXKRYSGM/T0TfCXJx8X0qIxQSHHtZJDxbLhpqxJhFIx
YDSjUzBRMB0GA1UdDgQWBBQExample123456789abcdefghijklmno0HwYDVR0j
BBgwFoAUExample123456789abcdefghijklmno0DwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAANJADBGAiEAExample123456789abcdefghijAhEA1234
-----END CERTIFICATE-----"#;

/// Convert DER bytes to PEM string
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----", label));
    pem
}

/// Get NIST Trust Anchor as PEM
pub fn nist_trust_anchor_pem() -> String {
    der_to_pem(NIST_TRUST_ANCHOR_DER, "CERTIFICATE")
}

/// Get NIST Good CA as PEM
pub fn nist_good_ca_pem() -> String {
    der_to_pem(NIST_GOOD_CA_DER, "CERTIFICATE")
}

/// Get NIST Valid EE as PEM
pub fn nist_valid_ee_pem() -> String {
    der_to_pem(NIST_VALID_EE_DER, "CERTIFICATE")
}
