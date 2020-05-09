use crate::crypto::Crypter;
use crate::error::Error;

// A crypter that simply passes data on.
pub struct PlaintextCrypter;

impl Crypter for PlaintextCrypter {
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(data.to_vec())
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(data.to_vec())
    }

    fn expected_ciphertext_length(&self, plaintext_length: usize) -> usize {
        plaintext_length
    }
}
