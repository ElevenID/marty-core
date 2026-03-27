//! Generated namespace constants
//! DO NOT EDIT - Generated from schema/namespaces.yaml

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// ISO 18013-5 mobile driving license namespaces
pub mod iso18013 {
    #[cfg(feature = "python")]
    use super::*;

    /// ISO 18013-5 mobile driving license namespaces
    pub mod namespace {
        
        /// Base namespace for ISO 18013-5.1 mDL data elements
        pub const MDL: &str = "org.iso.18013.5.1";
        
        /// AAMVA-specific extension namespace
        pub const AAMVA: &str = "org.iso.18013.5.1.aamva";
        
    }

    /// ISO 18013-5 document types
    pub mod doc_type {
        
        /// Mobile Driving License document type
        pub const MDL: &str = "org.iso.18013.5.1.mDL";
        
        /// Mobile ID document type
        pub const MID: &str = "org.iso.18013.5.1.mID";
        
        /// Mobile Passport document type (future)
        pub const MPASSPORT: &str = "org.iso.18013.5.1.mPassport";
        
    }

    /// ISO 18013-5 standard data element identifiers
    pub mod element {
        
        /// Family name (surname)
        pub const FAMILY_NAME: &str = "family_name";
        
        /// Given name (first name)
        pub const GIVEN_NAME: &str = "given_name";
        
        /// Date of birth
        pub const BIRTH_DATE: &str = "birth_date";
        
        /// Document expiration date
        pub const EXPIRY_DATE: &str = "expiry_date";
        
        /// Document issue date
        pub const ISSUE_DATE: &str = "issue_date";
        
        /// ISO 3166-1 alpha-2 country code
        pub const ISSUING_COUNTRY: &str = "issuing_country";
        
        /// Issuing authority name
        pub const ISSUING_AUTHORITY: &str = "issuing_authority";
        
        /// Document number
        pub const DOCUMENT_NUMBER: &str = "document_number";
        
        /// Portrait image (JPEG)
        pub const PORTRAIT: &str = "portrait";
        
        /// Signature or usual mark image
        pub const SIGNATURE: &str = "signature_usual_mark";
        
        /// Age verification: over 18
        pub const AGE_OVER_18: &str = "age_over_18";
        
        /// Age verification: over 21
        pub const AGE_OVER_21: &str = "age_over_21";
        
        /// Age verification: over 25
        pub const AGE_OVER_25: &str = "age_over_25";
        
        /// Age verification: over 62
        pub const AGE_OVER_62: &str = "age_over_62";
        
        /// Exact age in years
        pub const AGE_IN_YEARS: &str = "age_in_years";
        
        /// Birth year only
        pub const AGE_BIRTH_YEAR: &str = "age_birth_year";
        
        /// Driving privilege categories
        pub const DRIVING_PRIVILEGES: &str = "driving_privileges";
        
        /// UN distinguishing sign
        pub const UN_DISTINGUISHING_SIGN: &str = "un_distinguishing_sign";
        
        /// Sex (ISO/IEC 5218)
        pub const SEX: &str = "sex";
        
        /// Height in cm
        pub const HEIGHT: &str = "height";
        
        /// Weight in kg
        pub const WEIGHT: &str = "weight";
        
        /// Eye color
        pub const EYE_COLOUR: &str = "eye_colour";
        
        /// Hair color
        pub const HAIR_COLOUR: &str = "hair_colour";
        
        /// Place of birth
        pub const BIRTH_PLACE: &str = "birth_place";
        
        /// Resident address
        pub const RESIDENT_ADDRESS: &str = "resident_address";
        
        /// Portrait capture date
        pub const PORTRAIT_CAPTURE_DATE: &str = "portrait_capture_date";
        
        /// Nationality (ISO 3166-1 alpha-2)
        pub const NATIONALITY: &str = "nationality";
        
        /// City of residence
        pub const RESIDENT_CITY: &str = "resident_city";
        
        /// State/province of residence
        pub const RESIDENT_STATE: &str = "resident_state";
        
        /// Postal code of residence
        pub const RESIDENT_POSTAL_CODE: &str = "resident_postal_code";
        
        /// Country of residence
        pub const RESIDENT_COUNTRY: &str = "resident_country";
        
    }

    #[cfg(feature = "python")]
    #[pyclass(name = "Iso18013Namespace")]
    #[derive(Clone)]
    pub struct PyIso18013Namespace;

    #[cfg(feature = "python")]
    #[pymethods]
    impl PyIso18013Namespace {
        #[classattr]
        const MDL: &'static str = namespace::MDL;
        #[classattr]
        const AAMVA: &'static str = namespace::AAMVA;
    }

    #[cfg(feature = "python")]
    #[pyclass(name = "Iso18013DocType")]
    #[derive(Clone)]
    pub struct PyIso18013DocType;

    #[cfg(feature = "python")]
    #[pymethods]
    impl PyIso18013DocType {
        #[classattr]
        const MDL: &'static str = doc_type::MDL;
        #[classattr]
        const MID: &'static str = doc_type::MID;
        #[classattr]
        const MPASSPORT: &'static str = doc_type::MPASSPORT;
    }
}

/// W3C Verifiable Credentials contexts and types
pub mod w3c {
    #[cfg(feature = "python")]
    use super::*;

    /// W3C Verifiable Credentials contexts and types
    pub mod context {
        
        /// W3C Verifiable Credentials v1.0 context
        pub const CREDENTIALS_V1: &str = "https://www.w3.org/2018/credentials/v1";
        
        /// W3C VC examples context
        pub const CREDENTIALS_EXAMPLES_V1: &str = "https://www.w3.org/2018/credentials/examples/v1";
        
        /// Ed25519 signature suite 2018
        pub const ED25519_2018: &str = "https://w3id.org/security/suites/ed25519-2018/v1";
        
        /// Ed25519 signature suite 2020
        pub const ED25519_2020: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
        
        /// JSON Web Signature 2020
        pub const JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";
        
    }

    /// W3C VC credential types
    pub mod credential_type {
        
        /// Base verifiable credential type
        pub const VERIFIABLE_CREDENTIAL: &str = "VerifiableCredential";
        
        /// Base verifiable presentation type
        pub const VERIFIABLE_PRESENTATION: &str = "VerifiablePresentation";
        
    }

    #[cfg(feature = "python")]
    #[pyclass(name = "W3cContext")]
    #[derive(Clone)]
    pub struct PyW3cContext;

    #[cfg(feature = "python")]
    #[pymethods]
    impl PyW3cContext {
        
        #[classattr]
        const CREDENTIALS_V1: &'static str = context::CREDENTIALS_V1;
        
        #[classattr]
        const CREDENTIALS_EXAMPLES_V1: &'static str = context::CREDENTIALS_EXAMPLES_V1;
        
        #[classattr]
        const ED25519_2018: &'static str = context::ED25519_2018;
        
        #[classattr]
        const ED25519_2020: &'static str = context::ED25519_2020;
        
        #[classattr]
        const JWS_2020: &'static str = context::JWS_2020;
        
    }
}

/// Credential format identifiers
pub mod credential_format {
    #[cfg(feature = "python")]
    use super::*;

    
    /// JWT-encoded W3C VC (JSON)
    pub const JWT_VC_JSON: &str = "jwt_vc_json";
    
    /// JWT-encoded W3C VP (JSON)
    pub const JWT_VP_JSON: &str = "jwt_vp_json";
    
    /// Linked Data Proof VC
    pub const LDP_VC: &str = "ldp_vc";
    
    /// Linked Data Proof VP
    pub const LDP_VP: &str = "ldp_vp";
    
    /// Mobile Security Object mDoc (ISO 18013-5)
    pub const MSO_MDOC: &str = "mso_mdoc";
    
    /// Selective Disclosure JWT
    pub const VC_SD_JWT: &str = "vc+sd-jwt";
    
    /// Key-bound JWT VC
    pub const KB_JWT_VC: &str = "kb+jwt_vc_json";
    

    #[cfg(feature = "python")]
    #[pyclass(name = "CredentialFormat")]
    #[derive(Clone)]
    pub struct PyCredentialFormat;

    #[cfg(feature = "python")]
    #[pymethods]
    impl PyCredentialFormat {
        
        #[classattr]
        const JWT_VC_JSON: &'static str = JWT_VC_JSON;
        
        #[classattr]
        const JWT_VP_JSON: &'static str = JWT_VP_JSON;
        
        #[classattr]
        const LDP_VC: &'static str = LDP_VC;
        
        #[classattr]
        const LDP_VP: &'static str = LDP_VP;
        
        #[classattr]
        const MSO_MDOC: &'static str = MSO_MDOC;
        
        #[classattr]
        const VC_SD_JWT: &'static str = VC_SD_JWT;
        
        #[classattr]
        const KB_JWT_VC: &'static str = KB_JWT_VC;
        
    }
}

#[cfg(feature = "python")]
pub fn register_namespace_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<iso18013::PyIso18013Namespace>()?;
    parent_module.add_class::<iso18013::PyIso18013DocType>()?;
    parent_module.add_class::<w3c::PyW3cContext>()?;
    parent_module.add_class::<credential_format::PyCredentialFormat>()?;
    Ok(())
}