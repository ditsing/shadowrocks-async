use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;

use crate::Error;
use crate::Result;

use super::Crypter;
use super::NonceType;

macro_rules! define_sodium_crypter {
    ($name:ident, $namespace:ident) => {
        pub struct $name {
            key: $namespace::Key,
            nonce: $namespace::Nonce,
            nonce_type: NonceType,
        }

        impl $name {
            pub const KEY_BYTES: usize = $namespace::KEYBYTES;
            pub const NONCE_BYTES: usize = $namespace::NONCEBYTES;
            pub const TAG_BYTES: usize = $namespace::TAGBYTES;

            pub fn create_crypter(
                key_bytes: &[u8],
                nonce_type: NonceType,
            ) -> Self {
                Self {
                    key: $namespace::Key::from_slice(key_bytes)
                        .expect("Error creating crypter"),
                    nonce: $namespace::Nonce::from_slice(
                        &[0u8; Self::NONCE_BYTES],
                    )
                    .expect("Error creating nonce"),
                    nonce_type,
                }
            }
        }

        impl Crypter for $name {
            fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
                let ret = $namespace::seal(&data, None, &self.nonce, &self.key);
                if let NonceType::Sequential = self.nonce_type {
                    self.nonce.increment_le_inplace()
                }
                Ok(ret)
            }

            fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
                let ret = $namespace::open(&data, None, &self.nonce, &self.key);
                if let NonceType::Sequential = self.nonce_type {
                    self.nonce.increment_le_inplace()
                }
                ret.map_err(|_e| Error::DecryptionError)
            }

            fn expected_ciphertext_length(
                &self,
                plaintext_length: usize,
            ) -> usize {
                plaintext_length + Self::TAG_BYTES
            }
        }
    };
}

define_sodium_crypter!(XChacha20IetfPoly1305Crypter, xchacha20poly1305_ietf);
define_sodium_crypter!(Chacha20IetfPoly1305Crypter, chacha20poly1305_ietf);

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

    fn make_crypter_x(nonce_type: NonceType) -> XChacha20IetfPoly1305Crypter {
        XChacha20IetfPoly1305Crypter::create_crypter(
            vec![1u8; chacha20poly1305_ietf::KEYBYTES].as_slice(),
            nonce_type,
        )
    }

    #[test]
    fn test_encryption_decryption_x() -> Result<()> {
        let mut encrypter = make_crypter_x(NonceType::Sequential);
        let plaintext = vec![2u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        assert_eq!(
            ciphertext1,
            crypto_vec![
                0x17, 0x53, 0x95, 0xD7, 0x42, 0x63, 0x57, 0xFC,
                0x7B, 0x46, 0x6E, 0xE0, 0xDB, 0x6B, 0xA3, 0x00,
                0x2C, 0x83, 0xBE, 0xE8, 0x80, 0x74, 0x04, 0x38,
                0x97, 0x6D, 0xC7, 0x55, 0x75, 0x89, 0x12, 0xC8,
                0xAC, 0x21, 0x70, 0x38, 0x05, 0xDB, 0xD8, 0x3F,
                0x05, 0x94, 0x29, 0x7A, 0x29, 0x5D, 0xDE, 0xFF,
                0xE2, 0xCB, 0x4A, 0xE4, 0xD9
            ],
        );
        assert_eq!(
            ciphertext2,
            crypto_vec![
                0x4D, 0x97, 0x44, 0x0D, 0x78, 0x68, 0x5E, 0xE5,
                0xCC, 0x3A, 0x50, 0x5E, 0xF1, 0x8F, 0x8B, 0x03,
                0xB6, 0xB7, 0x5A, 0x30, 0xC1, 0x97, 0xC9, 0xA3,
                0x6C, 0x2B, 0xC2, 0xD7, 0x66, 0x1A, 0x01, 0x60,
                0xE9, 0x18, 0x23, 0x15, 0xEA, 0xF8, 0xE7, 0x07,
                0x25, 0x3C, 0x9A, 0x95, 0x5B, 0x0E, 0x3B, 0x51,
                0xC0, 0x37, 0x1F, 0xF7, 0x52
            ],
        );
        assert_ne!(ciphertext1, ciphertext2);

        let mut decrypter = make_crypter_x(NonceType::Sequential);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;
        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);

        Ok(())
    }

    #[test]
    fn test_encryption_decryption_zero_nonce_x() -> Result<()> {
        let mut encrypter = make_crypter_x(NonceType::Zero);
        let plaintext = vec![3u8; 37];
        let ciphertext1 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;
        let ciphertext2 =
            Crypter::encrypt(&mut encrypter, plaintext.as_slice())?;

        assert_eq!(
            ciphertext1,
            crypto_vec![
                0x16, 0x52, 0x94, 0xD6, 0x43, 0x62, 0x56, 0xFD,
                0x7A, 0x47, 0x6F, 0xE1, 0xDA, 0x6A, 0xA2, 0x01,
                0x2D, 0x82, 0xBF, 0xE9, 0x81, 0x75, 0x05, 0x39,
                0x96, 0x6C, 0xC6, 0x54, 0x74, 0x88, 0x13, 0xC9,
                0xAD, 0x20, 0x71, 0x39, 0x04, 0x73, 0x00, 0xB5,
                0xB4, 0x8F, 0x0C, 0x40, 0xB5, 0x36, 0xDC, 0x63,
                0x1E, 0x63, 0x4C, 0x31, 0x86
            ],
        );
        assert_eq!(ciphertext1, ciphertext2);

        let mut decrypter = make_crypter_x(NonceType::Zero);
        let decrypted_text1 =
            Crypter::decrypt(&mut decrypter, ciphertext1.as_slice())?;
        let decrypted_text2 =
            Crypter::decrypt(&mut decrypter, ciphertext2.as_slice())?;

        assert_eq!(decrypted_text1, plaintext);
        assert_eq!(decrypted_text2, plaintext);

        Ok(())
    }

    #[test]
    fn test_expected_ciphertext_length_x() {
        let mut data = Vec::with_capacity(1024);
        let mut crypter = make_crypter_x(NonceType::Sequential);
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

        assert_eq!(
            super::super::LARGE_NONCE_BYTES,
            XChacha20IetfPoly1305Crypter::NONCE_BYTES
        );
        assert_eq!(
            super::super::TAG_BYTES,
            XChacha20IetfPoly1305Crypter::TAG_BYTES
        );
    }
}
