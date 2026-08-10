//! Near Field Communication (NFC) transport implementation
//!
//! Implements ISO 18013-5 NFC transport using PC/SC smart card interface.

#[cfg(any(feature = "nfc", test))]
use super::Result;
#[cfg(feature = "nfc")]
use super::Transport;
#[cfg(feature = "nfc")]
use async_trait::async_trait;
#[cfg(feature = "nfc")]
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
#[cfg(feature = "nfc")]
use std::sync::{Arc, Mutex};

/// ISO 7816-4 APDU command structure
#[cfg(any(feature = "nfc", test))]
#[derive(Debug, Clone)]
struct Apdu {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u32>,
}

#[cfg(any(feature = "nfc", test))]
#[cfg_attr(not(feature = "nfc"), allow(dead_code))]
impl Apdu {
    const MAX_DATA_LENGTH: usize = u16::MAX as usize;

    /// Encode APDU to bytes
    fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.data.len() > Self::MAX_DATA_LENGTH {
            return Err(crate::error::Error::SendFailed(format!(
                "APDU data exceeds {} byte extended-length limit",
                Self::MAX_DATA_LENGTH
            )));
        }
        if self.le == Some(0) || self.le.is_some_and(|le| le > 65_536) {
            return Err(crate::error::Error::SendFailed(
                "APDU Le must be between 1 and 65536".to_string(),
            ));
        }

        let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];
        let extended = self.data.len() > u8::MAX as usize || self.le.is_some_and(|le| le > 256);

        if !self.data.is_empty() {
            if extended {
                bytes.push(0x00);
                bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
            } else {
                bytes.push(self.data.len() as u8);
            }
            bytes.extend_from_slice(&self.data);
        } else if extended {
            bytes.push(0x00);
        }

        if let Some(le) = self.le {
            if extended {
                let encoded = if le == 65_536 { 0 } else { le as u16 };
                bytes.extend_from_slice(&encoded.to_be_bytes());
            } else {
                bytes.push(if le == 256 { 0 } else { le as u8 });
            }
        }

        Ok(bytes)
    }

    /// Create SELECT APDU
    fn select(aid: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: aid.to_vec(),
            le: Some(256),
        }
    }

    /// Create GET DATA APDU
    fn get_data(tag: u16) -> Self {
        Self {
            cla: 0x00,
            ins: 0xCA,
            p1: ((tag >> 8) & 0xFF) as u8,
            p2: (tag & 0xFF) as u8,
            data: Vec::new(),
            le: Some(65_536),
        }
    }

    /// Create ENVELOPE APDU for sending data
    fn envelope(data: Vec<u8>, chained: bool) -> Self {
        Self {
            cla: if chained { 0x10 } else { 0x00 },
            ins: 0xC3,
            p1: 0x00,
            p2: 0x00,
            data,
            le: Some(256),
        }
    }

    fn envelope_chunks(data: &[u8]) -> Vec<Self> {
        if data.is_empty() {
            return vec![Self::envelope(Vec::new(), false)];
        }
        let chunk_count = data.len().div_ceil(Self::MAX_DATA_LENGTH);
        data.chunks(Self::MAX_DATA_LENGTH)
            .enumerate()
            .map(|(index, chunk)| Self::envelope(chunk.to_vec(), index + 1 < chunk_count))
            .collect()
    }
}

#[cfg(feature = "nfc")]
/// NFC transport for ISO 18013-5
pub struct NfcTransport {
    context: Arc<Mutex<Option<Context>>>,
    card: Arc<Mutex<Option<Card>>>,
    connected: bool,
    /// ISO 18013-5 AID
    mdl_aid: Vec<u8>,
}

#[cfg(feature = "nfc")]
impl NfcTransport {
    fn uninitialized() -> Self {
        Self {
            context: Arc::new(Mutex::new(None)),
            card: Arc::new(Mutex::new(None)),
            connected: false,
            // ISO 18013-5 mDL AID: A0000002480200
            mdl_aid: vec![0xA0, 0x00, 0x00, 0x02, 0x48, 0x02, 0x00],
        }
    }

    /// Create a new NFC transport
    pub fn new() -> Result<Self> {
        Ok(Self::uninitialized())
    }

    /// Connect to NFC reader and card
    async fn connect_card(&mut self) -> Result<()> {
        // Initialize PC/SC context
        let ctx = Context::establish(Scope::User)
            .map_err(|e| crate::error::Error::Transport(format!("PCSC context error: {}", e)))?;

        // List available readers
        let mut readers_buf = [0; 2048];
        let mut readers = ctx
            .list_readers(&mut readers_buf)
            .map_err(|e| crate::error::Error::Transport(format!("No NFC readers found: {}", e)))?;

        let reader = readers
            .next()
            .ok_or_else(|| crate::error::Error::Transport("No NFC reader available".to_string()))?;

        // Connect to card
        let card = ctx
            .connect(reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| {
                crate::error::Error::ConnectionFailed(format!("Card connection failed: {}", e))
            })?;

        // Select mDL application
        let select_apdu = Apdu::select(&self.mdl_aid);
        let response = self.transmit_apdu(&card, &select_apdu)?;

        // Check SW1SW2 = 0x9000 (success)
        if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(crate::error::Error::Transport(
                "Failed to select mDL application".to_string(),
            ));
        }

        *self.context.lock().map_err(|_| {
            crate::error::Error::Transport("NFC context mutex poisoned".to_string())
        })? = Some(ctx);
        *self
            .card
            .lock()
            .map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))? =
            Some(card);
        self.connected = true;

        Ok(())
    }

    /// Transmit APDU command to card
    fn transmit_apdu(&self, card: &Card, apdu: &Apdu) -> Result<Vec<u8>> {
        let mut response_buf = vec![0; 65_538];
        let command = apdu.to_bytes()?;

        let response = card
            .transmit(&command, &mut response_buf)
            .map_err(|e| crate::error::Error::Transport(format!("APDU transmit failed: {}", e)))?;

        Ok(response.to_vec())
    }

    /// Extract data from APDU response (excluding SW1SW2)
    fn extract_data(response: &[u8]) -> Result<Vec<u8>> {
        if response.len() < 2 {
            return Err(crate::error::Error::ReceiveFailed(
                "Invalid response".to_string(),
            ));
        }

        let sw1 = response[response.len() - 2];
        let sw2 = response[response.len() - 1];

        if sw1 == 0x90 && sw2 == 0x00 {
            Ok(response[..response.len() - 2].to_vec())
        } else {
            Err(crate::error::Error::ReceiveFailed(format!(
                "APDU error: SW={:02X}{:02X}",
                sw1, sw2
            )))
        }
    }
}

#[cfg(feature = "nfc")]
impl Default for NfcTransport {
    fn default() -> Self {
        Self::uninitialized()
    }
}

#[cfg(feature = "nfc")]
#[async_trait]
impl Transport for NfcTransport {
    async fn connect(&mut self) -> Result<()> {
        self.connect_card().await
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let card_guard = self
            .card
            .lock()
            .map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))?;
        let card = card_guard
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No card connected".to_string()))?;

        // Send data using ENVELOPE command
        for apdu in Apdu::envelope_chunks(data) {
            let response = self.transmit_apdu(card, &apdu)?;
            Self::extract_data(&response)?;
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let card_guard = self
            .card
            .lock()
            .map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))?;
        let card = card_guard
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No card connected".to_string()))?;

        // Get response data (tag 0x53 - device response)
        let apdu = Apdu::get_data(0x53);
        let response = self.transmit_apdu(card, &apdu)?;

        Self::extract_data(&response)
    }

    async fn close(&mut self) -> Result<()> {
        *self
            .card
            .lock()
            .map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))? =
            None;
        *self.context.lock().map_err(|_| {
            crate::error::Error::Transport("NFC context mutex poisoned".to_string())
        })? = None;
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(not(feature = "nfc"))]
/// NFC transport stub when feature is disabled
pub struct NfcTransport;

#[cfg(not(feature = "nfc"))]
impl NfcTransport {
    pub fn new() -> crate::error::Result<Self> {
        Err(crate::error::Error::TransportNotSupported)
    }
}

#[cfg(test)]
mod apdu_tests {
    use super::Apdu;

    #[test]
    fn short_apdu_encodes_255_byte_lc_without_truncation() {
        let apdu = Apdu::envelope(vec![0xaa; 255], false).to_bytes().unwrap();
        assert_eq!(apdu[4], 255);
        assert_eq!(apdu.len(), 4 + 1 + 255 + 1);
    }

    #[test]
    fn extended_apdu_encodes_256_byte_lc() {
        let apdu = Apdu::envelope(vec![0xbb; 256], false).to_bytes().unwrap();
        assert_eq!(&apdu[4..7], &[0x00, 0x01, 0x00]);
        assert_eq!(apdu.len(), 4 + 3 + 256 + 2);
    }

    #[test]
    fn oversized_payload_is_chained_without_data_loss() {
        let data = vec![0x5a; Apdu::MAX_DATA_LENGTH + 37];
        let chunks = Apdu::envelope_chunks(&data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].cla, 0x10);
        assert_eq!(chunks[1].cla, 0x00);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.data.len()).sum::<usize>(),
            data.len()
        );
        assert!(chunks.iter().all(|chunk| chunk.to_bytes().is_ok()));
    }

    #[test]
    fn single_apdu_rejects_data_beyond_extended_limit() {
        let apdu = Apdu::envelope(vec![0; Apdu::MAX_DATA_LENGTH + 1], false);
        assert!(apdu.to_bytes().is_err());
    }
}
