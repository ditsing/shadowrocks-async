use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

use crate::Error;
use crate::Result;

use super::*;

// openssl::symm::Crypter is not used since it requires a fixed iv. We use the incrementing nonce
// as iv, which means that a new Crypter object must be constructed for each invocation of
// encrypt() / decrypt(). Instead, we use the convenient function decrypt_aead() and encrypt_aead().
pub struct OpensslCrypter {
    cipher: Cipher,
    key: Vec<u8>,
    nonce_type: NonceType,
    nonce: u32,
}

impl OpensslCrypter {
    pub fn create(cipher: Cipher, key: &[u8], nonce_type: NonceType) -> Self {
        Self {
            cipher,
            key: key.to_vec(),
            nonce_type,
            nonce: 0,
        }
    }

    pub fn encrypt(
        &mut self,
        data: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_BYTES])> {
        let mut tag = [0u8; TAG_BYTES];
        // An empty aad is a no-op and should be handled gracefully by the library.
        let result = encrypt_aead(
            self.cipher,
            self.key.as_slice(),
            Some(&self.nonce_bytes()),
            &[],
            data,
            &mut tag,
        );
        match result {
            Ok(ciphertext) => {
                self.increment_nonce();
                Ok((ciphertext, tag))
            }
            Err(e) => {
                log::error!("Error encrypting data with OpenSSL {}", e);
                Err(Error::EncryptionError)
            }
        }
    }

    pub fn decrypt(
        &mut self,
        data: &[u8],
        tag: &[u8; TAG_BYTES],
    ) -> Result<Vec<u8>> {
        // An empty aad is a no-op and should be handled gracefully by the library.
        let result = decrypt_aead(
            self.cipher,
            self.key.as_slice(),
            Some(&self.nonce_bytes()),
            &[],
            data,
            tag,
        );
        match result {
            Ok(plaintext) => {
                self.increment_nonce();
                Ok(plaintext)
            }
            Err(e) => {
                log::error!("Error decrypting data with OpenSSL: {}", e);
                Err(Error::DecryptionError)
            }
        }
    }

    fn increment_nonce(&mut self) {
        if let NonceType::Sequential = self.nonce_type {
            self.nonce += 1
        }
    }

    // This function allocates and copies memory frequently. A better version might be to keep the
    // bytes array in the struct and simulate the increment operation.
    fn nonce_bytes(&self) -> [u8; NONCE_BYTES] {
        let mut ret = [0u8; NONCE_BYTES];
        let mut n = self.nonce;

        ret[0] = (n & ((1 << 8) - 1)) as u8;

        n >>= 8;
        ret[1] = (n & ((1 << 8) - 1)) as u8;

        n >>= 8;
        ret[2] = (n & ((1 << 8) - 1)) as u8;

        n >>= 8;
        ret[3] = (n & ((1 << 8) - 1)) as u8;

        ret
    }
}

impl Crypter for OpensslCrypter {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (mut ciphertext, tag) = self.encrypt(plaintext)?;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_BYTES {
            log::error!("Ciphertext is too short to decrypt.");
            return Err(Error::DecryptionError);
        }

        let tag_start = ciphertext.len() - TAG_BYTES;
        let mut tag = [0u8; TAG_BYTES];
        tag.clone_from_slice(&ciphertext[tag_start..tag_start + TAG_BYTES]);
        self.decrypt(&ciphertext[..tag_start], &tag)
    }

    // Round plaintext length up to block size of the cipher.
    // This function is useful when deciding whether enough data has been received from network to
    // pass the authenticity check.
    fn expected_ciphertext_length(&self, plaintext_length: usize) -> usize {
        let block_size = self.cipher.block_size();
        let last_block = if plaintext_length % block_size == 0 {
            0
        } else {
            1
        };
        (plaintext_length / block_size + last_block) * block_size + TAG_BYTES
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(crypto_array, crypto_vec)]
mod test {
    use super::*;

    fn make_crypter(nonce_type: NonceType) -> OpensslCrypter {
        let key = vec![1u8; Cipher::aes_256_gcm().key_len()];
        OpensslCrypter::create(
            Cipher::aes_256_gcm(),
            key.as_slice(),
            nonce_type,
        )
    }

    #[test]
    fn test_encryption_decryption() -> Result<()> {
        let mut encrypter = make_crypter(NonceType::Sequential);
        let plaintext = vec![2u8; 37];
        let ciphertext =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;

        assert_eq!(
            ciphertext,
            crypto_vec![
                0xBD, 0x37, 0x9A, 0xDE, 0x77, 0x39, 0x01, 0xBD,
                0x91, 0x7B, 0x90, 0x47, 0x73, 0x26, 0xC3, 0x43,
                0xB7, 0xC4, 0x9D, 0xB2, 0x87, 0x9D, 0x36, 0xF8,
                0xCE, 0x26, 0x0C, 0xD7, 0x0C, 0xD4, 0x6C, 0x19,
                0x5C, 0xBA, 0xAF, 0xF9, 0x51, 0x13, 0xE4, 0xF3,
                0x2D, 0xC0, 0xA2, 0x59, 0x72, 0xEA, 0xF3, 0x95,
                0x3D, 0x51, 0x1A, 0x05, 0xBA
            ],
        );
        assert_eq!(1, encrypter.nonce);

        let mut decrypter = make_crypter(NonceType::Sequential);
        let decrypted_text =
            Crypter::decrypt(&mut decrypter, ciphertext.as_slice())?;

        assert_eq!(decrypted_text, plaintext);
        assert_eq!(1, decrypter.nonce);
        Ok(())
    }

    #[test]
    fn test_multiple_encryption_decryption() -> Result<()> {
        let mut encrypter = make_crypter(NonceType::Sequential);
        let plaintext = vec![3u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;

        assert_eq!(
            ciphertext1,
            crypto_vec![
                0xBC, 0x36, 0x9B, 0xDF, 0x76, 0x38, 0x00, 0xBC,
                0x90, 0x7A, 0x91, 0x46, 0x72, 0x27, 0xC2, 0x42,
                0xB6, 0xC5, 0x9C, 0xB3, 0x86, 0x9C, 0x37, 0xF9,
                0xCF, 0x27, 0x0D, 0xD6, 0x0D, 0xD5, 0x6D, 0x18,
                0x5D, 0xBB, 0xAE, 0xF8, 0x50, 0xB0, 0x3C, 0xA5,
                0x92, 0x9D, 0x26, 0xF2, 0x0F, 0x3A, 0x09, 0xE5,
                0xF8, 0x6A, 0x40, 0x61, 0xF4
            ]
        );
        assert_eq!(
            ciphertext2,
            crypto_vec![
                0x54, 0x94, 0x1F, 0x3B, 0x2B, 0x5D, 0xFC, 0x59,
                0xD4, 0x26, 0xAE, 0xB1, 0xA5, 0x10, 0xFF, 0x60,
                0x32, 0x8F, 0xFB, 0xC5, 0xCB, 0x72, 0xD0, 0xED,
                0xF5, 0xBA, 0xE5, 0x93, 0xC3, 0x79, 0x5A, 0x33,
                0x4F, 0x27, 0x2B, 0x94, 0x75, 0x50, 0x74, 0x22,
                0x23, 0x03, 0xF3, 0x59, 0x22, 0xAA, 0xE2, 0x7D,
                0x97, 0x52, 0xB9, 0x84, 0x0E
            ]
        );
        assert_ne!(ciphertext1, ciphertext2);
        assert_eq!(2, encrypter.nonce);

        let mut decrypter = make_crypter(NonceType::Sequential);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;

        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);
        assert_eq!(2, decrypter.nonce);

        Ok(())
    }

    #[test]
    fn test_encryption_decryption_zero_nonce() -> Result<()> {
        let mut encrypter = make_crypter(NonceType::Zero);
        let plaintext = vec![4u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;

        assert_eq!(
            ciphertext1,
            crypto_vec![
                0xBB, 0x31, 0x9C, 0xD8, 0x71, 0x3F, 0x07, 0xBB,
                0x97, 0x7D, 0x96, 0x41, 0x75, 0x20, 0xC5, 0x45,
                0xB1, 0xC2, 0x9B, 0xB4, 0x81, 0x9B, 0x30, 0xFE,
                0xC8, 0x20, 0x0A, 0xD1, 0x0A, 0xD2, 0x6A, 0x1F,
                0x5A, 0xBC, 0xA9, 0xFF, 0x57, 0x5F, 0x35, 0x04,
                0xAE, 0x0D, 0xB9, 0xA2, 0x7E, 0x08, 0xEE, 0xB7,
                0xA3, 0xCA, 0xC7, 0x5C, 0x1C
            ],
        );
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(0, encrypter.nonce);

        let mut decrypter = make_crypter(NonceType::Zero);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;

        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);
        assert_eq!(0, decrypter.nonce);

        Ok(())
    }

    #[test]
    fn test_expected_ciphertext_size() {
        let mut data = Vec::with_capacity(256);
        let mut crypter = make_crypter(NonceType::Sequential);
        // Clippy does not have this check on Rust stable (1.46.0).
        #[allow(clippy::unknown_clippy_lints)]
        #[allow(clippy::same_item_push)]
        for _ in 0..256 {
            data.push(5u8);
            let expected_size = crypter.expected_ciphertext_length(data.len());
            assert_eq!(
                expected_size,
                Crypter::encrypt(&mut crypter, data.as_slice())
                    .expect("encryption should not fail")
                    .len()
            );
        }
    }

    #[test]
    fn test_nonce_bytes() {
        let mut crypter = make_crypter(NonceType::Sequential);

        assert_eq!(
            crypter.nonce_bytes()[0..4].to_vec(),
            &[0x00u8, 0x00, 0x00, 0x00]
        );

        crypter.nonce = 18;
        assert_eq!(
            crypter.nonce_bytes()[0..4].to_vec(),
            &[0x12u8, 0x00, 0x00, 0x00]
        );

        crypter.nonce = 1025;
        assert_eq!(
            crypter.nonce_bytes()[0..4].to_vec(),
            &[0x01u8, 0x04, 0x00, 0x00]
        );

        crypter.nonce = 65537;
        assert_eq!(
            crypter.nonce_bytes()[0..4].to_vec(),
            &[0x01u8, 0x00, 0x01, 0x00]
        );

        crypter.nonce = 256 * 256 * 256 * 3 + 9;
        assert_eq!(
            crypter.nonce_bytes()[0..4].to_vec(),
            &[0x09u8, 0x00, 0x00, 0x03]
        );
    }
}
