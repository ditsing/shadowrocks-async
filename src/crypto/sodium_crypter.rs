use sodiumoxide::crypto::aead::chacha20poly1305_ietf;

use crate::Error;
use crate::Result;

use super::Crypter;
use super::NonceType;

pub struct Chacha20IetfPoly1305Crypter {
    key: chacha20poly1305_ietf::Key,
    nonce: chacha20poly1305_ietf::Nonce,
    nonce_type: NonceType,
}

impl Chacha20IetfPoly1305Crypter {
    pub const KEY_BYTES: usize = chacha20poly1305_ietf::KEYBYTES;
    pub const NONCE_BYTES: usize = chacha20poly1305_ietf::NONCEBYTES;
    pub const TAG_BYTES: usize = chacha20poly1305_ietf::TAGBYTES;

    pub fn create_crypter(key_bytes: &[u8], nonce_type: NonceType) -> Self {
        Self {
            key: chacha20poly1305_ietf::Key::from_slice(key_bytes)
                .expect("Error creating crypter"),
            nonce: chacha20poly1305_ietf::Nonce::from_slice(
                &[0u8; Self::NONCE_BYTES],
            )
            .expect("Error creating nonce"),
            nonce_type,
        }
    }
}

impl Crypter for Chacha20IetfPoly1305Crypter {
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ret =
            chacha20poly1305_ietf::seal(&data, None, &self.nonce, &self.key);
        if let NonceType::Sequential = self.nonce_type {
            self.nonce.increment_le_inplace()
        }
        Ok(ret)
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ret =
            chacha20poly1305_ietf::open(&data, None, &self.nonce, &self.key);
        if let NonceType::Sequential = self.nonce_type {
            self.nonce.increment_le_inplace()
        }
        ret.map_err(|_e| Error::DecryptionError)
    }

    fn expected_ciphertext_length(&self, plaintext_length: usize) -> usize {
        plaintext_length + Self::TAG_BYTES
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(crypto_array, crypto_vec)]
mod test {
    use super::*;

    fn make_crypter(nonce_type: NonceType) -> Chacha20IetfPoly1305Crypter {
        Chacha20IetfPoly1305Crypter::create_crypter(
            vec![1u8; chacha20poly1305_ietf::KEYBYTES].as_slice(),
            nonce_type,
        )
    }

    #[test]
    fn test_encryption_decryption() -> Result<()> {
        let mut encrypter = make_crypter(NonceType::Sequential);
        let plaintext = vec![2u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        assert_eq!(
            ciphertext1,
            crypto_vec![
                0x03, 0x25, 0x4F, 0xD3, 0xEC, 0x50, 0x14, 0xC0,
                0x06, 0xF9, 0x6B, 0x8F, 0xAC, 0xA6, 0x59, 0x50,
                0xEB, 0x89, 0x6D, 0x0D, 0xDF, 0x06, 0x6F, 0xCE,
                0x38, 0x84, 0xB9, 0x05, 0x9C, 0x34, 0xF2, 0x26,
                0x16, 0x7C, 0x49, 0x85, 0x5F, 0xCE, 0x8F, 0x0E,
                0xDF, 0xA0, 0x26, 0x56, 0x6B, 0x5B, 0xF9, 0x3C,
                0x54, 0xB6, 0x4E, 0x10, 0x4A
            ],
        );
        assert_eq!(
            ciphertext2,
            crypto_vec![
                0x00, 0x51, 0xAC, 0x62, 0x34, 0x4A, 0x28, 0xE7,
                0x5B, 0xCF, 0x21, 0x58, 0x1B, 0xFB, 0xD1, 0x35,
                0x86, 0x8F, 0x7B, 0xC3, 0x1E, 0x5C, 0xAE, 0x08,
                0x4B, 0x8B, 0x21, 0x1E, 0x44, 0xDE, 0xAD, 0xCD,
                0x13, 0x72, 0xB0, 0xC2, 0xB6, 0x09, 0x99, 0x9D,
                0xB3, 0xD4, 0xB9, 0x34, 0xFC, 0x44, 0x34, 0xFF,
                0x3B, 0xEF, 0x58, 0x71, 0xD3
            ],
        );
        assert_ne!(ciphertext1, ciphertext2);

        let mut decrypter = make_crypter(NonceType::Sequential);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;
        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);

        Ok(())
    }

    #[test]
    fn test_encryption_decryption_zero_nonce() -> Result<()> {
        let mut encrypter = make_crypter(NonceType::Zero);
        let plaintext = vec![3u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;

        assert_eq!(
            ciphertext1,
            crypto_vec![
                0x02, 0x24, 0x4E, 0xD2, 0xED, 0x51, 0x15, 0xC1,
                0x07, 0xF8, 0x6A, 0x8E, 0xAD, 0xA7, 0x58, 0x51,
                0xEA, 0x88, 0x6C, 0x0C, 0xDE, 0x07, 0x6E, 0xCF,
                0x39, 0x85, 0xB8, 0x04, 0x9D, 0x35, 0xF3, 0x27,
                0x17, 0x7D, 0x48, 0x84, 0x5E, 0x77, 0xC8, 0xB6,
                0xC8, 0x89, 0x28, 0xDB, 0xB6, 0xC2, 0x44, 0xA5,
                0x11, 0x1B, 0x52, 0xB4, 0x75
            ],
        );
        assert_eq!(ciphertext1, ciphertext2);

        let mut decrypter = make_crypter(NonceType::Zero);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;

        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);

        Ok(())
    }

    #[test]
    fn test_expected_ciphertext_length() {
        let mut data = Vec::with_capacity(1024);
        let mut crypter = make_crypter(NonceType::Sequential);
        for _ in 0..1024 {
            data.push(5u8);
            let expected_size = crypter.expected_ciphertext_length(data.len());
            assert_eq!(
                expected_size,
                crypter
                    .encrypt(data.as_slice())
                    .expect("encryption should not fail")
                    .len()
            );
        }
    }

    #[test]
    fn test_size_assumptions() {
        assert_eq!(
            super::super::NONCE_BYTES,
            Chacha20IetfPoly1305Crypter::NONCE_BYTES
        );
        assert_eq!(
            super::super::TAG_BYTES,
            Chacha20IetfPoly1305Crypter::TAG_BYTES
        );
    }
}
