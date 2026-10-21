// Copyright 2026 ElevenID
// SPDX-License-Identifier: Apache-2.0 OR MIT

use zeroize::Zeroize;

pub(crate) struct SensitiveBuffer {
    pub(crate) bytes: Vec<u8>,
    #[cfg(test)]
    cleanup_observer: Option<SensitiveBufferCleanupObserver>,
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct SensitiveBufferCleanupObserver(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

#[cfg(test)]
impl SensitiveBufferCleanupObserver {
    pub(crate) fn snapshots(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

impl SensitiveBuffer {
    pub(crate) fn copied_from(bytes: &[u8], extra_capacity: usize) -> Self {
        let mut output = Vec::with_capacity(bytes.len().saturating_add(extra_capacity));
        output.extend_from_slice(bytes);
        Self {
            bytes: output,
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn copied_from_with_observer(
        bytes: &[u8],
        extra_capacity: usize,
        observer: SensitiveBufferCleanupObserver,
    ) -> Self {
        let mut output = Self::copied_from(bytes, extra_capacity);
        output.cleanup_observer = Some(observer);
        output
    }

    #[cfg(any(feature = "symmetric", feature = "emrtd-compat"))]
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        self.bytes.resize(self.bytes.capacity(), 0);
        self.bytes.fill(0);
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer.0.lock().unwrap().push(self.bytes.clone());
        }
        self.bytes.zeroize();
    }
}
