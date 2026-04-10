//! Near Field Communication (NFC) transport implementation
//!
//! Implements ISO 18013-5 NFC transport using PC/SC smart card interface.

#[cfg(feature = "nfc")]
use super::{Result, Transport};
#[cfg(feature = "nfc")]
use async_trait::async_trait;
#[cfg(feature = "nfc")]
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
#[cfg(feature = "nfc")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "nfc")]
/// ISO 7816-4 APDU command structure
#[derive(Debug, Clone)]
struct Apdu {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u8>,
}

#[cfg(feature = "nfc")]
impl Apdu {
    /// Encode APDU to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];
        
        if !self.data.is_empty() {
            debug_assert!(self.data.len() <= 255, "APDU data exceeds short-form Lc limit");
            bytes.push(self.data.len() as u8);
            bytes.extend_from_slice(&self.data);
        }
        
        if let Some(le) = self.le {
            bytes.push(le);
        }
        
        bytes
    }

    /// Create SELECT APDU
    fn select(aid: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: aid.to_vec(),
            le: Some(0x00),
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
            le: Some(0x00),
        }
    }

    /// Create ENVELOPE APDU for sending data
    fn envelope(data: Vec<u8>) -> Self {
        Self {
            cla: 0x00,
            ins: 0xC3,
            p1: 0x00,
            p2: 0x00,
            data,
            le: Some(0x00),
        }
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
    /// Create a new NFC transport
    pub fn new() -> Result<Self> {
        // ISO 18013-5 mDL AID: A0000002480200
        let mdl_aid = vec![0xA0, 0x00, 0x00, 0x02, 0x48, 0x02, 0x00];
        
        Ok(Self {
            context: Arc::new(Mutex::new(None)),
            card: Arc::new(Mutex::new(None)),
            connected: false,
            mdl_aid,
        })
    }

    /// Connect to NFC reader and card
    async fn connect_card(&mut self) -> Result<()> {
        // Initialize PC/SC context
        let ctx = Context::establish(Scope::User)
            .map_err(|e| crate::error::Error::Transport(format!("PCSC context error: {}", e)))?;

        // List available readers
        let mut readers_buf = [0; 2048];
        let mut readers = ctx.list_readers(&mut readers_buf)
            .map_err(|e| crate::error::Error::Transport(format!("No NFC readers found: {}", e)))?;

        let reader = readers.next()
            .ok_or_else(|| crate::error::Error::Transport("No NFC reader available".to_string()))?;

        // Connect to card
        let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| crate::error::Error::ConnectionFailed(format!("Card connection failed: {}", e)))?;

        // Select mDL application
        let select_apdu = Apdu::select(&self.mdl_aid);
        let response = self.transmit_apdu(&card, &select_apdu)?;
        
        // Check SW1SW2 = 0x9000 (success)
        if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(crate::error::Error::Transport("Failed to select mDL application".to_string()));
        }

        *self.context.lock().map_err(|_| crate::error::Error::Transport("NFC context mutex poisoned".to_string()))? = Some(ctx);
        *self.card.lock().map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))? = Some(card);
        self.connected = true;

        Ok(())
    }

    /// Transmit APDU command to card
    fn transmit_apdu(&self, card: &Card, apdu: &Apdu) -> Result<Vec<u8>> {
        let mut response_buf = [0; 512];
        let command = apdu.to_bytes();
        
        let response_len = card.transmit(&command, &mut response_buf)
            .map_err(|e| crate::error::Error::Transport(format!("APDU transmit failed: {}", e)))?;

        Ok(response_buf[..response_len].to_vec())
    }

    /// Extract data from APDU response (excluding SW1SW2)
    fn extract_data(response: &[u8]) -> Result<Vec<u8>> {
        if response.len() < 2 {
            return Err(crate::error::Error::ReceiveFailed("Invalid response".to_string()));
        }

        let sw1 = response[response.len() - 2];
        let sw2 = response[response.len() - 1];

        if sw1 == 0x90 && sw2 == 0x00 {
            Ok(response[..response.len() - 2].to_vec())
        } else {
            Err(crate::error::Error::ReceiveFailed(
                format!("APDU error: SW={:02X}{:02X}", sw1, sw2)
            ))
        }
    }
}

#[cfg(feature = "nfc")]
impl Default for NfcTransport {
    fn default() -> Self {
        Self::new().expect("NfcTransport::new() failed during Default construction")
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
            return Err(crate::error::Error::ConnectionFailed("Not connected".to_string()));
        }

        let card_guard = self.card.lock().map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))?;
        let card = card_guard.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No card connected".to_string()))?;

        // Send data using ENVELOPE command
        let apdu = Apdu::envelope(data.to_vec());
        let response = self.transmit_apdu(card, &apdu)?;

        // Check for success
        Self::extract_data(&response)?;

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed("Not connected".to_string()));
        }

        let card_guard = self.card.lock().map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))?;
        let card = card_guard.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No card connected".to_string()))?;

        // Get response data (tag 0x53 - device response)
        let apdu = Apdu::get_data(0x53);
        let response = self.transmit_apdu(card, &apdu)?;

        Self::extract_data(&response)
    }

    async fn close(&mut self) -> Result<()> {
        *self.card.lock().map_err(|_| crate::error::Error::Transport("NFC card mutex poisoned".to_string()))? = None;
        *self.context.lock().map_err(|_| crate::error::Error::Transport("NFC context mutex poisoned".to_string()))? = None;
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
    pub fn new() -> Result<(), crate::error::Error> {
        Err(crate::error::Error::TransportNotSupported)
    }
}
