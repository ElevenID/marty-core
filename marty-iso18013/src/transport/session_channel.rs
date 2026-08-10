//! Fail-closed coupling between an established session and its transport.

use super::Transport;
use crate::{Result, Session};

/// Owns a native transport together with its cryptographic session.
///
/// Any send/receive failure or explicit close terminates the session so a
/// caller cannot accidentally continue using counters after a disconnect.
pub struct SessionChannel<T: Transport> {
    session: Session,
    transport: T,
}

impl<T: Transport> SessionChannel<T> {
    /// Connect a transport for an existing session.
    pub async fn connect(session: Session, mut transport: T) -> Result<Self> {
        if let Err(error) = transport.connect().await {
            session.terminate().await?;
            return Err(error);
        }
        Ok(Self { session, transport })
    }

    /// Encrypt and send one protocol message.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let ciphertext = self.session.send_encrypted(plaintext).await?;
        if let Err(error) = self.transport.send(&ciphertext).await {
            self.session.terminate().await?;
            return Err(error);
        }
        Ok(())
    }

    /// Receive and authenticate one protocol message.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let ciphertext = match self.transport.receive().await {
            Ok(value) => value,
            Err(error) => {
                self.session.terminate().await?;
                return Err(error);
            }
        };
        match self.session.receive_encrypted(&ciphertext).await {
            Ok(value) => Ok(value),
            Err(error) => {
                self.session.terminate().await?;
                Err(error)
            }
        }
    }

    /// Close the transport and terminate the cryptographic session.
    pub async fn close(&mut self) -> Result<()> {
        let transport_result = self.transport.close().await;
        self.session.terminate().await?;
        transport_result
    }

    /// Access the session for state inspection.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Access the transport for transport-specific configuration.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;
    use crate::{DeviceEngagement, SessionConfig, SessionState};

    async fn established_device_session() -> Session {
        let engagement = DeviceEngagement::new_qr().unwrap();
        let device = Session::from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();
        let reader = Session::reader_from_engagement(&engagement, SessionConfig::default())
            .await
            .unwrap();
        device.establish(&reader.public_key().await).await.unwrap();
        device
    }

    #[tokio::test]
    async fn explicit_transport_close_terminates_session() {
        let session = established_device_session().await;
        let mut channel = SessionChannel::connect(session, MockTransport::new())
            .await
            .unwrap();
        channel.close().await.unwrap();
        assert_eq!(channel.session().state().await, SessionState::Terminated);
    }

    #[tokio::test]
    async fn transport_disconnect_fails_closed_and_terminates_session() {
        let session = established_device_session().await;
        let mut channel = SessionChannel::connect(session, MockTransport::new())
            .await
            .unwrap();
        channel.transport_mut().close().await.unwrap();

        assert!(channel.send(b"must not survive disconnect").await.is_err());
        assert_eq!(channel.session().state().await, SessionState::Terminated);
    }
}
