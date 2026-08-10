//! Synchronous PyO3 adapters over the native asynchronous transports.

use std::future::Future;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::transport::{HttpsTransport, Transport};

fn run_transport<T>(future: impl Future<Output = crate::Result<T>>) -> PyResult<T> {
    tokio::runtime::Runtime::new()
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?
        .block_on(future)
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))
}

#[pyclass(name = "HttpsTransport")]
pub struct PyHttpsTransport {
    inner: HttpsTransport,
}

#[pymethods]
impl PyHttpsTransport {
    #[new]
    fn new(url: String) -> Self {
        Self {
            inner: HttpsTransport::new(url),
        }
    }

    fn connect(&mut self) -> PyResult<()> {
        run_transport(self.inner.connect())
    }

    fn send(&mut self, data: &[u8]) -> PyResult<()> {
        run_transport(self.inner.send(data))
    }

    fn receive(&mut self) -> PyResult<Vec<u8>> {
        run_transport(self.inner.receive())
    }

    fn close(&mut self) -> PyResult<()> {
        run_transport(self.inner.close())
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

#[cfg(feature = "ble")]
use crate::transport::BleTransport;

#[cfg(feature = "ble")]
#[pyclass(name = "BleTransport")]
pub struct PyBleTransport {
    inner: BleTransport,
}

#[cfg(feature = "ble")]
#[pymethods]
impl PyBleTransport {
    #[new]
    #[pyo3(signature = (service_uuid=None))]
    fn new(service_uuid: Option<&str>) -> PyResult<Self> {
        let inner = match service_uuid {
            Some(uuid) => BleTransport::with_service_uuid(uuid)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
            None => BleTransport::new(),
        };
        Ok(Self { inner })
    }

    fn connect(&mut self) -> PyResult<()> {
        run_transport(self.inner.connect())
    }

    fn send(&mut self, data: &[u8]) -> PyResult<()> {
        run_transport(self.inner.send(data))
    }

    fn receive(&mut self) -> PyResult<Vec<u8>> {
        run_transport(self.inner.receive())
    }

    fn close(&mut self) -> PyResult<()> {
        run_transport(self.inner.close())
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

#[cfg(feature = "nfc")]
use crate::transport::NfcTransport;

#[cfg(feature = "nfc")]
#[pyclass(name = "NfcTransport")]
pub struct PyNfcTransport {
    inner: NfcTransport,
}

#[cfg(feature = "nfc")]
#[pymethods]
impl PyNfcTransport {
    #[new]
    fn new() -> PyResult<Self> {
        NfcTransport::new()
            .map(|inner| Self { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    fn connect(&mut self) -> PyResult<()> {
        run_transport(self.inner.connect())
    }

    fn send(&mut self, data: &[u8]) -> PyResult<()> {
        run_transport(self.inner.send(data))
    }

    fn receive(&mut self) -> PyResult<Vec<u8>> {
        run_transport(self.inner.receive())
    }

    fn close(&mut self) -> PyResult<()> {
        run_transport(self.inner.close())
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHttpsTransport>()?;
    #[cfg(feature = "ble")]
    m.add_class::<PyBleTransport>()?;
    #[cfg(feature = "nfc")]
    m.add_class::<PyNfcTransport>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_transport_connection_lifecycle() {
        let mut transport = PyHttpsTransport::new("https://example.invalid/mdl".to_string());
        assert!(!transport.is_connected());
        transport.connect().expect("connect should initialize state");
        assert!(transport.is_connected());
        transport.close().expect("close should clear state");
        assert!(!transport.is_connected());
    }
}
