//! Core ISO 18013-5 protocol structures
//!
//! This module implements the fundamental data structures for the ISO 18013-5
//! protocol, including device engagement, transport methods, and engagement methods.

use crate::error::{Error, Result};
use isomdl::definitions::device_engagement::{
    BleOptions, DeviceRetrievalMethod, NfcOptions, PeripheralServerMode, Security,
};
use isomdl::definitions::device_key::cose_key::EC2Y;
use isomdl::definitions::helpers::{NonEmptyVec, Tag24};
use isomdl::definitions::{CoseKey, EC2Curve};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Transport method for ISO 18013-5 communication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub enum TransportMethod {
    /// Bluetooth Low Energy
    BLE,
    /// Near Field Communication
    NFC,
    /// WiFi Aware
    WiFiAware,
    /// HTTPS
    HTTPS,
}

/// Engagement method for initiating communication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub enum EngagementMethod {
    /// QR code scanning
    QR,
    /// NFC tag reading
    NFC,
}

/// Device engagement structure containing connection information
///
/// The DeviceEngagement structure is used by the mdoc/mDL holder to advertise
/// its availability and provide connection parameters to potential readers.
#[derive(Clone)]
#[cfg_attr(feature = "python", pyclass(skip_from_py_object))]
pub struct DeviceEngagement {
    /// Protocol version (currently "1.0")
    pub version: String,

    /// Available transport methods and their parameters
    pub transports: Vec<TransportInfo>,

    /// Engagement method used
    pub engagement_method: EngagementMethod,

    /// Device public key for ECDH (P-256 uncompressed point)
    pub device_key: Vec<u8>,

    /// Optional device-specific data
    pub device_data: Option<HashMap<String, Vec<u8>>>,

    /// Private half of EDeviceKey for holder-side session establishment.
    ///
    /// This is present only on an engagement generated locally. It is never
    /// serialized, exposed to Python, or included in debug output.
    ephemeral_secret: Option<Vec<u8>>,
}

impl fmt::Debug for DeviceEngagement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceEngagement")
            .field("version", &self.version)
            .field("transports", &self.transports)
            .field("engagement_method", &self.engagement_method)
            .field("device_key", &self.device_key)
            .field("device_data", &self.device_data)
            .field("has_ephemeral_secret", &self.ephemeral_secret.is_some())
            .finish()
    }
}

/// Transport-specific connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportInfo {
    /// Transport method type
    pub method: TransportMethod,

    /// Transport-specific parameters (e.g., BLE UUID, IP address)
    pub parameters: HashMap<String, Vec<u8>>,
}

impl DeviceEngagement {
    /// Create a new device engagement for QR code presentation
    pub fn new_qr() -> Result<Self> {
        let (ephemeral_secret, device_key) = Self::generate_device_key()?;

        Ok(Self {
            version: "1.0".to_string(),
            transports: Vec::new(),
            engagement_method: EngagementMethod::QR,
            device_key,
            device_data: None,
            ephemeral_secret: Some(ephemeral_secret),
        })
    }

    /// Add a BLE transport with the given service UUID
    pub fn add_ble_transport(&mut self, service_uuid: &str) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("serviceUuid".to_string(), service_uuid.as_bytes().to_vec());

        self.transports.push(TransportInfo {
            method: TransportMethod::BLE,
            parameters: params,
        });

        Ok(())
    }

    /// Add an NFC data-retrieval transport.
    pub fn add_nfc_transport(&mut self) -> Result<()> {
        self.transports.push(TransportInfo {
            method: TransportMethod::NFC,
            parameters: HashMap::new(),
        });

        Ok(())
    }

    /// Add an HTTPS transport with the given URL
    pub fn add_https_transport(&mut self, url: &str) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("url".to_string(), url.as_bytes().to_vec());

        self.transports.push(TransportInfo {
            method: TransportMethod::HTTPS,
            parameters: params,
        });

        Ok(())
    }

    /// Generate a new ephemeral device key (P-256)
    fn generate_device_key() -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(marty_crypto::ecdh::p256_generate_keypair())
    }

    pub(crate) fn ephemeral_secret(&self) -> Option<&[u8]> {
        self.ephemeral_secret.as_deref()
    }

    pub(crate) fn cose_key_from_sec1(public_key: &[u8]) -> Result<CoseKey> {
        if public_key.len() != 65 || public_key.first() != Some(&0x04) {
            return Err(Error::InvalidEngagement(
                "EDeviceKey must be an uncompressed P-256 point".to_string(),
            ));
        }

        Ok(CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: public_key[1..33].to_vec(),
            y: EC2Y::Value(public_key[33..65].to_vec()),
        })
    }

    pub(crate) fn cose_key_to_sec1(cose_key: &CoseKey) -> Result<Vec<u8>> {
        match cose_key {
            CoseKey::EC2 {
                crv: EC2Curve::P256,
                x,
                y: EC2Y::Value(y),
            } if x.len() == 32 && y.len() == 32 => {
                let mut public_key = Vec::with_capacity(65);
                public_key.push(0x04);
                public_key.extend_from_slice(x);
                public_key.extend_from_slice(y);
                // Validate that the coordinates represent a point on P-256.
                marty_crypto::ecdh::P256KeyPair::generate().agree(&public_key)?;
                Ok(public_key)
            }
            _ => Err(Error::InvalidEngagement(
                "only an uncompressed P-256 EDeviceKey is supported".to_string(),
            )),
        }
    }

    fn to_iso(&self) -> Result<isomdl::definitions::DeviceEngagement> {
        if self.version != "1.0" {
            return Err(Error::InvalidEngagement(format!(
                "unsupported DeviceEngagement version {}",
                self.version
            )));
        }
        if self.device_data.is_some() {
            return Err(Error::InvalidEngagement(
                "device_data cannot be encoded as ISO 18013-5 protocolInfo".to_string(),
            ));
        }

        let device_key = Tag24::new(Self::cose_key_from_sec1(&self.device_key)?)
            .map_err(|error| Error::InvalidEngagement(error.to_string()))?;
        let mut retrieval_methods = Vec::new();

        for transport in &self.transports {
            match transport.method {
                TransportMethod::BLE => {
                    let uuid = transport
                        .parameters
                        .get("serviceUuid")
                        .ok_or_else(|| {
                            Error::InvalidEngagement(
                                "BLE transport is missing serviceUuid".to_string(),
                            )
                        })
                        .and_then(|value| {
                            std::str::from_utf8(value).map_err(|_| {
                                Error::InvalidEngagement("BLE serviceUuid is not UTF-8".to_string())
                            })
                        })
                        .and_then(|value| {
                            Uuid::parse_str(value).map_err(|error| {
                                Error::InvalidEngagement(format!(
                                    "invalid BLE serviceUuid: {error}"
                                ))
                            })
                        })?;
                    retrieval_methods.push(DeviceRetrievalMethod::BLE(BleOptions {
                        peripheral_server_mode: Some(PeripheralServerMode {
                            uuid,
                            ble_device_address: None,
                        }),
                        central_client_mode: None,
                    }));
                }
                TransportMethod::NFC => {
                    retrieval_methods.push(DeviceRetrievalMethod::NFC(NfcOptions::default()))
                }
                TransportMethod::WiFiAware => {
                    return Err(Error::InvalidEngagement(
                        "Wi-Fi Aware parameters are not implemented".to_string(),
                    ));
                }
                TransportMethod::HTTPS => {
                    return Err(Error::InvalidEngagement(
                        "HTTPS is a server-retrieval transport and cannot be encoded as a device retrieval method"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(isomdl::definitions::DeviceEngagement {
            version: self.version.clone(),
            security: Security(1, device_key),
            device_retrieval_methods: NonEmptyVec::maybe_new(retrieval_methods),
            server_retrieval_methods: None,
            protocol_info: None,
        })
    }

    fn from_iso(value: isomdl::definitions::DeviceEngagement) -> Result<Self> {
        if value.version != "1.0" || value.security.0 != 1 {
            return Err(Error::InvalidEngagement(
                "unsupported DeviceEngagement version or cipher suite".to_string(),
            ));
        }
        if value.server_retrieval_methods.is_some() || value.protocol_info.is_some() {
            return Err(Error::InvalidEngagement(
                "server retrieval and protocolInfo are not supported".to_string(),
            ));
        }

        let device_key = Self::cose_key_to_sec1(value.security.1.as_ref())?;
        let mut transports = Vec::new();
        if let Some(methods) = value.device_retrieval_methods {
            for method in methods.iter() {
                match method {
                    DeviceRetrievalMethod::BLE(options) => {
                        let uuid = match (
                            options.peripheral_server_mode.as_ref(),
                            options.central_client_mode.as_ref(),
                        ) {
                            (Some(mode), _) => mode.uuid,
                            (None, Some(mode)) => mode.uuid,
                            (None, None) => {
                                return Err(Error::InvalidEngagement(
                                    "BLE retrieval method enables neither mode".to_string(),
                                ));
                            }
                        };
                        let mut parameters = HashMap::new();
                        parameters.insert(
                            "serviceUuid".to_string(),
                            uuid.hyphenated().to_string().into_bytes(),
                        );
                        transports.push(TransportInfo {
                            method: TransportMethod::BLE,
                            parameters,
                        });
                    }
                    DeviceRetrievalMethod::NFC(_) => transports.push(TransportInfo {
                        method: TransportMethod::NFC,
                        parameters: HashMap::new(),
                    }),
                    DeviceRetrievalMethod::WIFI(_) => {
                        return Err(Error::InvalidEngagement(
                            "Wi-Fi Aware parameters are not implemented".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(Self {
            version: value.version,
            transports,
            engagement_method: EngagementMethod::QR,
            device_key,
            device_data: None,
            ephemeral_secret: None,
        })
    }

    /// Encode the device engagement as CBOR
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        isomdl::cbor::to_vec(&self.to_iso()?)
            .map_err(|error| Error::InvalidEngagement(error.to_string()))
    }

    /// Decode device engagement from CBOR
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let value: isomdl::definitions::DeviceEngagement =
            ciborium::de::from_reader(&mut cursor).map_err(Error::CborDecode)?;
        if cursor.position() != data.len() as u64 {
            return Err(Error::InvalidEngagement(
                "trailing bytes after DeviceEngagement".to_string(),
            ));
        }
        Self::from_iso(value)
    }

    /// Encode this DeviceEngagement as the ISO `mdoc:` URI carried by a QR code.
    pub fn to_qr_uri(&self) -> Result<String> {
        Tag24::new(self.to_iso()?)
            .map_err(|error| Error::InvalidEngagement(error.to_string()))?
            .to_qr_code_uri()
            .map_err(|error| Error::QrCode(error.to_string()))
    }

    /// Decode and validate an ISO `mdoc:` QR payload.
    pub fn from_qr_uri(uri: &str) -> Result<Self> {
        let tagged = Tag24::<isomdl::definitions::DeviceEngagement>::from_qr_code_uri(uri)
            .map_err(|error| Error::InvalidEngagement(error.to_string()))?;
        Self::from_cbor(&tagged.inner_bytes)
    }

    /// Generate a QR code containing the device engagement
    pub fn to_qr_code(&self) -> Result<Vec<u8>> {
        use image::Luma;
        use qrcode::QrCode;

        let uri = self.to_qr_uri()?;
        let code = QrCode::new(uri.as_bytes()).map_err(|e| Error::QrCode(e.to_string()))?;

        let image = code.render::<Luma<u8>>().build();
        let mut buffer = Vec::new();
        image
            .write_to(
                &mut std::io::Cursor::new(&mut buffer),
                image::ImageFormat::Png,
            )
            .map_err(|e| Error::QrCode(e.to_string()))?;

        Ok(buffer)
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl DeviceEngagement {
    #[staticmethod]
    fn new() -> PyResult<Self> {
        Self::new_qr().map_err(|e| e.into())
    }

    fn add_ble(&mut self, service_uuid: &str) -> PyResult<()> {
        self.add_ble_transport(service_uuid).map_err(|e| e.into())
    }

    fn add_nfc(&mut self) -> PyResult<()> {
        self.add_nfc_transport().map_err(|e| e.into())
    }

    fn add_https(&mut self, url: &str) -> PyResult<()> {
        self.add_https_transport(url).map_err(|e| e.into())
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.to_cbor().map_err(|e| e.into())
    }

    fn to_uri(&self) -> PyResult<String> {
        self.to_qr_uri().map_err(Into::into)
    }

    #[pyo3(name = "to_qr_code")]
    fn to_qr_code_py(&self) -> PyResult<Vec<u8>> {
        self.to_qr_code().map_err(|e| e.into())
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Self::from_cbor(data).map_err(|e| e.into())
    }

    #[staticmethod]
    fn from_uri(uri: &str) -> PyResult<Self> {
        Self::from_qr_uri(uri).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_engagement_creation() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        assert_eq!(engagement.version, "1.0");
        assert_eq!(engagement.engagement_method, EngagementMethod::QR);
        assert!(!engagement.device_key.is_empty());
    }

    #[test]
    fn test_add_transports() {
        let mut engagement = DeviceEngagement::new_qr().unwrap();
        engagement
            .add_ble_transport("0000FFF0-0000-1000-8000-00805F9B34FB")
            .unwrap();
        engagement.add_nfc_transport().unwrap();
        engagement
            .add_https_transport("https://example.com/mdl")
            .unwrap();

        assert_eq!(engagement.transports.len(), 3);
        assert_eq!(engagement.transports[0].method, TransportMethod::BLE);
        assert_eq!(engagement.transports[1].method, TransportMethod::NFC);
        assert_eq!(engagement.transports[2].method, TransportMethod::HTTPS);
    }

    #[test]
    fn test_cbor_roundtrip() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let cbor = engagement.to_cbor().unwrap();
        let decoded = DeviceEngagement::from_cbor(&cbor).unwrap();

        assert_eq!(engagement.version, decoded.version);
        assert_eq!(engagement.device_key, decoded.device_key);
    }

    #[test]
    fn test_qr_uri_roundtrip_and_strict_prefix() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let uri = engagement.to_qr_uri().unwrap();
        assert!(uri.starts_with("mdoc:"));

        let decoded = DeviceEngagement::from_qr_uri(&uri).unwrap();
        assert_eq!(decoded.device_key, engagement.device_key);
        assert!(
            DeviceEngagement::from_qr_uri(uri.replacen("mdoc:", "https:", 1).as_str()).is_err()
        );
    }

    #[test]
    fn test_iso_qr_golden_vector_is_accepted() {
        // Published by the isomdl conformance suite and encoded according to
        // ISO 18013-5 DeviceEngagementBytes URI rules.
        const ISO_QR: &str = "mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgglyWXuAyJ6iRNc8OlYXenvkJt23rJPdtIhlawXqr-yf0iWCC1GQSH8tIwTYVwha_ZoPL20_saYXrGIbrCm133H0ki-QKBgwIBowD1AfQKUH2RiuAEbUVzrsrOiUnSPDw";
        let decoded = DeviceEngagement::from_qr_uri(ISO_QR).unwrap();
        assert_eq!(decoded.version, "1.0");
        assert_eq!(decoded.device_key.len(), 65);
        assert!(!decoded.transports.is_empty());
    }

    #[test]
    fn test_cbor_rejects_trailing_and_malformed_data() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let mut cbor = engagement.to_cbor().unwrap();
        cbor.push(0x00);
        assert!(DeviceEngagement::from_cbor(&cbor).is_err());
        assert!(DeviceEngagement::from_cbor(&[0xff, 0xff]).is_err());
    }
}
