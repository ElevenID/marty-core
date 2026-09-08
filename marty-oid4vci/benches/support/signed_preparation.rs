use marty_oid4vci::Oid4vciResult;

pub trait PreparedAssembly: Sized {
    type Output;

    fn signing_payload(&self) -> &[u8];
    fn assemble(self, signature: &[u8]) -> Self::Output;
}

pub struct SignedPreparation<T: PreparedAssembly> {
    prepared: T,
    signature: Vec<u8>,
}

impl<T: PreparedAssembly> SignedPreparation<T> {
    pub fn try_sign(
        prepared: T,
        sign: impl FnOnce(&[u8]) -> Oid4vciResult<Vec<u8>>,
    ) -> Oid4vciResult<Self> {
        let signature = sign(prepared.signing_payload())?;
        Ok(Self {
            prepared,
            signature,
        })
    }

    pub fn assemble(self) -> T::Output {
        self.prepared.assemble(&self.signature)
    }
}
