//! Python adapters for certificate builder.

use super::*;

/// Python-friendly certificate profile enum.
#[cfg(feature = "cert-builder")]
#[pyclass(name = "CertProfile", from_py_object)]
#[derive(Clone)]
pub struct PyCertProfile {
    inner: marty_crypto::cert_builder::CertProfile,
}

#[cfg(feature = "cert-builder")]
#[pymethods]
impl PyCertProfile {
    /// Create a CA profile with optional path length constraint.
    #[staticmethod]
    fn ca(path_length: Option<u8>) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Ca { path_length },
        }
    }

    /// Create a SubCA profile with path length constraint.
    #[staticmethod]
    fn sub_ca(path_length: u8) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::SubCa { path_length },
        }
    }

    /// Create an EndEntity (leaf) profile.
    #[staticmethod]
    fn end_entity() -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::EndEntity,
        }
    }

    /// Create a CSCA profile for eMRTD.
    #[staticmethod]
    fn csca(country_code: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Csca {
                country_code: country_code.to_string(),
            },
        }
    }

    /// Create an IACA profile for mDL.
    #[staticmethod]
    fn iaca(jurisdiction: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Iaca {
                jurisdiction: jurisdiction.to_string(),
            },
        }
    }

    /// Create a DSC profile for eMRTD document signer.
    #[staticmethod]
    fn dsc(country_code: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Dsc {
                country_code: country_code.to_string(),
            },
        }
    }

    fn __repr__(&self) -> String {
        format!("CertProfile({:?})", self.inner)
    }
}

/// Python-friendly certificate builder configuration.
#[cfg(feature = "cert-builder")]
#[pyclass(name = "CertificateBuilderConfig", from_py_object)]
#[derive(Clone)]
pub struct PyCertificateBuilderConfig {
    subject_cn: Option<String>,
    subject_country: Option<String>,
    subject_org: Option<String>,
    subject_ou: Option<String>,
    issuer_cn: Option<String>,
    validity_days: u32,
    profile: marty_crypto::cert_builder::CertProfile,
    key_type: String,
}

#[cfg(feature = "cert-builder")]
#[pymethods]
impl PyCertificateBuilderConfig {
    /// Create a new certificate builder configuration with defaults.
    #[new]
    fn new() -> Self {
        Self {
            subject_cn: None,
            subject_country: None,
            subject_org: None,
            subject_ou: None,
            issuer_cn: None,
            validity_days: 365,
            profile: marty_crypto::cert_builder::CertProfile::EndEntity,
            key_type: "ecdsa-p256".to_string(),
        }
    }

    /// Set the subject Common Name.
    fn subject_cn(&mut self, cn: &str) -> Self {
        self.subject_cn = Some(cn.to_string());
        self.clone()
    }

    /// Set the subject Country.
    fn subject_country(&mut self, country: &str) -> Self {
        self.subject_country = Some(country.to_string());
        self.clone()
    }

    /// Set the subject Organization.
    fn subject_org(&mut self, org: &str) -> Self {
        self.subject_org = Some(org.to_string());
        self.clone()
    }

    /// Set the subject Organizational Unit.
    fn subject_ou(&mut self, ou: &str) -> Self {
        self.subject_ou = Some(ou.to_string());
        self.clone()
    }

    /// Set the issuer Common Name (for self-signed, this is optional).
    fn issuer_cn(&mut self, cn: &str) -> Self {
        self.issuer_cn = Some(cn.to_string());
        self.clone()
    }

    /// Set the validity period in days from now.
    fn validity_days(&mut self, days: u32) -> Self {
        self.validity_days = days;
        self.clone()
    }

    /// Set the certificate profile.
    fn profile(&mut self, profile: &PyCertProfile) -> Self {
        self.profile = profile.inner.clone();
        self.clone()
    }

    /// Set the key type: "ecdsa-p256", "ecdsa-p384", "rsa2048", "rsa3072", "rsa4096", "ed25519".
    fn key_type(&mut self, key_type: &str) -> Self {
        self.key_type = key_type.to_string();
        self.clone()
    }

    /// Build a self-signed certificate.
    ///
    /// Returns:
    ///     Tuple of (certificate_der_bytes, private_key_pem_str)
    fn build_self_signed<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, String)> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let (cert_der, key_pem) = config.build_self_signed().map_err(to_pyerr)?;

        Ok((PyBytes::new(py, &cert_der), key_pem))
    }

    /// Build a certificate signed by an issuer CA.
    ///
    /// Args:
    ///     issuer_cert_der: DER-encoded issuer certificate
    ///     issuer_key_pem: PEM-encoded issuer private key
    ///
    /// Returns:
    ///     Tuple of (certificate_der_bytes, private_key_pem_str)
    fn build_signed_by<'py>(
        &self,
        py: Python<'py>,
        issuer_cert_der: &[u8],
        issuer_key_pem: &str,
    ) -> PyResult<(Bound<'py, PyBytes>, String)> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let (cert_der, key_pem) = config
            .build_signed_by(issuer_cert_der, issuer_key_pem)
            .map_err(to_pyerr)?;

        Ok((PyBytes::new(py, &cert_der), key_pem))
    }

    /// Build a self-signed certificate from an existing private key.
    ///
    /// Args:
    ///     private_key_pem: PEM-encoded private key
    ///
    /// Returns:
    ///     DER-encoded certificate bytes
    fn build_self_signed_with_key<'py>(
        &self,
        py: Python<'py>,
        private_key_pem: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let cert_der = config
            .build_self_signed_with_key(private_key_pem)
            .map_err(to_pyerr)?;

        Ok(PyBytes::new(py, &cert_der))
    }

    fn __repr__(&self) -> String {
        format!(
            "CertificateBuilderConfig(subject_cn={:?}, validity_days={}, key_type={})",
            self.subject_cn, self.validity_days, self.key_type
        )
    }
}

/// Create a self-signed certificate with the given parameters.
///
/// This is a convenience function for simple certificate generation.
///
/// Args:
///     common_name: Subject Common Name
///     validity_days: Certificate validity in days (default: 365)
///     key_type: Key type (default: "ecdsa-p256")
///     is_ca: Whether this is a CA certificate (default: False)
///     country: Subject country code (optional)
///     organization: Subject organization (optional)
///
/// Returns:
///     Tuple of (certificate_der_bytes, private_key_pem_str)
#[cfg(feature = "cert-builder")]
#[pyfunction]
pub(super) fn build_self_signed_certificate<'py>(
    py: Python<'py>,
    common_name: &str,
    validity_days: Option<u32>,
    key_type: Option<&str>,
    is_ca: Option<bool>,
    country: Option<&str>,
    organization: Option<&str>,
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    use marty_crypto::cert_builder::{CertProfile, CertificateBuilderConfig, DistinguishedName};
    use marty_crypto::keygen::KeyType;

    let validity_days = validity_days.unwrap_or(365);
    let key_type_str = key_type.unwrap_or("ecdsa-p256");
    let is_ca = is_ca.unwrap_or(false);

    // Build distinguished name
    let mut subject = DistinguishedName::new().cn(common_name);
    if let Some(c) = country {
        subject = subject.country(c);
    }
    if let Some(o) = organization {
        subject = subject.organization(o);
    }

    // Parse key type
    let key_type = match key_type_str.to_lowercase().as_str() {
        "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
        "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
        "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
        "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
        "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
        "ed25519" => KeyType::Ed25519,
        _ => return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", key_type_str)
        )),
    };

    // Determine profile
    let profile = if is_ca {
        CertProfile::Ca { path_length: None }
    } else {
        CertProfile::EndEntity
    };

    // Build the certificate
    let config = CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(profile)
        .key_type(key_type);

    let (cert_der, key_pem) = config.build_self_signed().map_err(to_pyerr)?;

    Ok((PyBytes::new(py, &cert_der), key_pem))
}

/// Create a self-signed certificate using an existing private key.
///
/// Args:
///     private_key_pem: PEM-encoded private key
///     common_name: Subject Common Name
///     validity_days: Certificate validity in days (default: 365)
///     key_type: Key type hint (required if key type cannot be auto-detected)
///     is_ca: Whether this is a CA certificate (default: False)
///     country: Subject country code (optional)
///     organization: Subject organization (optional)
///
/// Returns:
///     DER-encoded certificate bytes
#[cfg(feature = "cert-builder")]
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub(super) fn build_self_signed_certificate_with_key<'py>(
    py: Python<'py>,
    private_key_pem: &str,
    common_name: &str,
    validity_days: Option<u32>,
    key_type: Option<&str>,
    is_ca: Option<bool>,
    country: Option<&str>,
    organization: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::cert_builder::{CertProfile, CertificateBuilderConfig, DistinguishedName};
    use marty_crypto::keygen::KeyType;

    let validity_days = validity_days.unwrap_or(365);
    let is_ca = is_ca.unwrap_or(false);

    // Build distinguished name
    let mut subject = DistinguishedName::new().cn(common_name);
    if let Some(c) = country {
        subject = subject.country(c);
    }
    if let Some(o) = organization {
        subject = subject.organization(o);
    }

    // Auto-detect or use provided key type
    let key_type = if let Some(kt) = key_type {
        match kt.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unsupported key type: {}",
                    kt
                )))
            }
        }
    } else {
        // Try to auto-detect from PEM
        if private_key_pem.contains("EC PRIVATE KEY") || private_key_pem.len() < 500 {
            KeyType::EcdsaP256
        } else if private_key_pem.contains("RSA PRIVATE KEY") || private_key_pem.len() > 1000 {
            KeyType::Rsa2048
        } else if private_key_pem.contains("ED25519") {
            KeyType::Ed25519
        } else {
            KeyType::EcdsaP256 // Default fallback
        }
    };

    // Determine profile
    let profile = if is_ca {
        CertProfile::Ca { path_length: None }
    } else {
        CertProfile::EndEntity
    };

    // Build the certificate
    let config = CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(profile)
        .key_type(key_type);

    let cert_der = config
        .build_self_signed_with_key(private_key_pem)
        .map_err(to_pyerr)?;

    Ok(PyBytes::new(py, &cert_der))
}
