//! Core ISO 18013-5 protocol structures
//!
//! This module implements the fundamental data structures for the ISO 18013-5
//! protocol, including device engagement, transport methods, and engagement methods.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Transport method for ISO 18013-5 communication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
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
#[cfg_attr(feature = "python", pyclass)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
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
        let device_key = Self::generate_device_key()?;

        Ok(Self {
            version: "1.0".to_string(),
            transports: Vec::new(),
            engagement_method: EngagementMethod::QR,
            device_key,
            device_data: None,
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
    fn generate_device_key() -> Result<Vec<u8>> {
        use marty_crypto::ecdh::P256KeyPair;

        let key_pair = P256KeyPair::generate();
        Ok(key_pair.public_key_uncompressed())
    }

    /// Encode the device engagement as CBOR
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Decode device engagement from CBOR
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(data).map_err(Error::CborDecode)
    }

    /// Generate a QR code containing the device engagement
    pub fn to_qr_code(&self) -> Result<Vec<u8>> {
        use image::Luma;
        use qrcode::QrCode;

        let cbor_data = self.to_cbor()?;
        let code = QrCode::new(cbor_data).map_err(|e| Error::QrCode(e.to_string()))?;

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

    fn add_https(&mut self, url: &str) -> PyResult<()> {
        self.add_https_transport(url).map_err(|e| e.into())
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.to_cbor().map_err(|e| e.into())
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Self::from_cbor(data).map_err(|e| e.into())
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
        engagement
            .add_https_transport("https://example.com/mdl")
            .unwrap();

        assert_eq!(engagement.transports.len(), 2);
        assert_eq!(engagement.transports[0].method, TransportMethod::BLE);
        assert_eq!(engagement.transports[1].method, TransportMethod::HTTPS);
    }

    #[test]
    fn test_cbor_roundtrip() {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let cbor = engagement.to_cbor().unwrap();
        let decoded = DeviceEngagement::from_cbor(&cbor).unwrap();

        assert_eq!(engagement.version, decoded.version);
        assert_eq!(engagement.device_key, decoded.device_key);
    }
}
