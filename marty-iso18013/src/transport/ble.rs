//! Bluetooth Low Energy (BLE) transport implementation
//!
//! Implements the ISO 18013-5 BLE transport using the MDL service UUID.

#[cfg(feature = "ble")]
use super::{Result, Transport};
#[cfg(feature = "ble")]
use async_trait::async_trait;
#[cfg(feature = "ble")]
use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
#[cfg(feature = "ble")]
use btleplug::platform::{Adapter, Manager, Peripheral};
#[cfg(feature = "ble")]
use std::time::Duration;
#[cfg(feature = "ble")]
use tokio::time::timeout;
#[cfg(feature = "ble")]
use uuid::Uuid;

#[cfg(feature = "ble")]
/// MDL BLE service UUID as per ISO 18013-5
const MDL_SERVICE_UUID: &str = "0000FFF0-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// State characteristic UUID
const CHAR_STATE: &str = "0000FFF1-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// Client to Server characteristic UUID
const CHAR_CLIENT2SERVER: &str = "0000FFF2-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// Server to Client characteristic UUID
const CHAR_SERVER2CLIENT: &str = "0000FFF3-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// Ident characteristic UUID
const CHAR_IDENT: &str = "0000FFF4-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// L2CAP characteristic UUID
const CHAR_L2CAP: &str = "0000FFF5-0000-1000-8000-00805F9B34FB";

#[cfg(feature = "ble")]
/// BLE transport for ISO 18013-5
pub struct BleTransport {
    peripheral: Option<Peripheral>,
    service_uuid: Uuid,
    client2server: Option<Characteristic>,
    server2client: Option<Characteristic>,
    connected: bool,
    /// MTU size for message fragmentation
    mtu: usize,
}

#[cfg(feature = "ble")]
impl BleTransport {
    /// Create a new BLE transport with default MDL service UUID
    pub fn new() -> Self {
        Self {
            peripheral: None,
            service_uuid: Uuid::parse_str(MDL_SERVICE_UUID).unwrap(),
            client2server: None,
            server2client: None,
            connected: false,
            mtu: 512, // Default MTU
        }
    }

    /// Create a new BLE transport with custom service UUID
    pub fn with_service_uuid(service_uuid: &str) -> Result<Self> {
        let uuid = Uuid::parse_str(service_uuid)
            .map_err(|e| crate::error::Error::Transport(format!("Invalid UUID: {}", e)))?;

        Ok(Self {
            peripheral: None,
            service_uuid: uuid,
            client2server: None,
            server2client: None,
            connected: false,
            mtu: 512,
        })
    }

    /// Discover and connect to an mDL device
    async fn discover_and_connect(&mut self) -> Result<()> {
        let manager = Manager::new()
            .await
            .map_err(|e| crate::error::Error::Transport(format!("BLE manager error: {}", e)))?;

        let adapters = manager
            .adapters()
            .await
            .map_err(|e| crate::error::Error::Transport(format!("No BLE adapters: {}", e)))?;

        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| crate::error::Error::Transport("No BLE adapter found".to_string()))?;

        // Start scanning
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Scan failed: {}", e)))?;

        // Wait for devices
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Find peripherals with MDL service
        let peripherals = adapter.peripherals().await.map_err(|e| {
            crate::error::Error::Transport(format!("Failed to get peripherals: {}", e))
        })?;

        for peripheral in peripherals {
            let properties = peripheral.properties().await.map_err(|e| {
                crate::error::Error::Transport(format!("Failed to get properties: {}", e))
            })?;

            if let Some(props) = properties {
                if props.services.contains(&self.service_uuid) {
                    // Found MDL device, connect
                    peripheral.connect().await.map_err(|e| {
                        crate::error::Error::ConnectionFailed(format!("Connection failed: {}", e))
                    })?;

                    peripheral.discover_services().await.map_err(|e| {
                        crate::error::Error::Transport(format!("Service discovery failed: {}", e))
                    })?;

                    // Find characteristics
                    let characteristics = peripheral.characteristics();
                    let c2s_uuid = Uuid::parse_str(CHAR_CLIENT2SERVER).unwrap();
                    let s2c_uuid = Uuid::parse_str(CHAR_SERVER2CLIENT).unwrap();

                    self.client2server =
                        characteristics.iter().find(|c| c.uuid == c2s_uuid).cloned();

                    self.server2client =
                        characteristics.iter().find(|c| c.uuid == s2c_uuid).cloned();

                    if self.client2server.is_some() && self.server2client.is_some() {
                        self.peripheral = Some(peripheral);
                        self.connected = true;

                        // Subscribe to notifications
                        if let (Some(peripheral), Some(char)) =
                            (&self.peripheral, &self.server2client)
                        {
                            peripheral.subscribe(char).await.map_err(|e| {
                                crate::error::Error::Transport(format!("Subscribe failed: {}", e))
                            })?;
                        }

                        return Ok(());
                    }
                }
            }
        }

        Err(crate::error::Error::ConnectionFailed(
            "No MDL device found".to_string(),
        ))
    }

    /// Fragment a message for BLE transmission
    fn fragment_message(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let chunk_size = self.mtu - 3; // Account for ATT header
        data.chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Reassemble fragmented messages
    fn reassemble_fragments(&self, fragments: Vec<Vec<u8>>) -> Vec<u8> {
        fragments.into_iter().flatten().collect()
    }
}

#[cfg(feature = "ble")]
impl Default for BleTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "ble")]
#[async_trait]
impl Transport for BleTransport {
    async fn connect(&mut self) -> Result<()> {
        self.discover_and_connect().await
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let peripheral = self
            .peripheral
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No peripheral".to_string()))?;

        let characteristic = self
            .client2server
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No characteristic".to_string()))?;

        // Fragment and send
        let fragments = self.fragment_message(data);
        for fragment in fragments {
            peripheral
                .write(characteristic, &fragment, WriteType::WithResponse)
                .await
                .map_err(|e| crate::error::Error::SendFailed(format!("BLE write failed: {}", e)))?;
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(crate::error::Error::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        let peripheral = self
            .peripheral
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No peripheral".to_string()))?;

        let characteristic = self
            .server2client
            .as_ref()
            .ok_or_else(|| crate::error::Error::Transport("No characteristic".to_string()))?;

        // Read from characteristic with timeout
        let result = timeout(Duration::from_secs(30), peripheral.read(characteristic))
            .await
            .map_err(|_| crate::error::Error::Timeout)?
            .map_err(|e| crate::error::Error::ReceiveFailed(format!("BLE read failed: {}", e)))?;

        Ok(result)
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(peripheral) = &self.peripheral {
            peripheral
                .disconnect()
                .await
                .map_err(|e| crate::error::Error::Transport(format!("Disconnect failed: {}", e)))?;
        }

        self.connected = false;
        self.peripheral = None;
        self.client2server = None;
        self.server2client = None;

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(not(feature = "ble"))]
/// BLE transport stub when feature is disabled
pub struct BleTransport;

#[cfg(not(feature = "ble"))]
impl BleTransport {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "ble"))]
impl Default for BleTransport {
    fn default() -> Self {
        Self::new()
    }
}
