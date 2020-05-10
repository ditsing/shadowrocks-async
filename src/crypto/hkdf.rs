#![cfg(not(feature = "ring-hkdf"))]
// HKDF implementation as instructed by https://en.wikipedia.org/wiki/HKDF and RFC5869.

pub trait Hash {
    fn digest_length(&self) -> usize;
    fn digest(&self, key: &[u8], msg: &[u8]) -> Vec<u8>;
}

pub struct Hkdf<T>
where
    T: Hash + Sized,
{
    prk: Vec<u8>,
    hash: T,
}

impl<T: Hash + Sized> Hkdf<T> {
    pub fn extract(
        salt_option: Option<&[u8]>,
        input_key_material: &[u8],
        hash: T,
    ) -> Self {
        let hash_len = hash.digest_length();
        // Using a vector to hold byte array.
        let salt = salt_option
            .map(|v| Vec::from(v))
            .unwrap_or(vec![0u8; hash_len]);
        Self {
            prk: hash.digest(salt.as_slice(), input_key_material),
            hash,
        }
    }

    pub fn expand(&self, info: &[u8], length: usize) -> Vec<u8> {
        let hash_len = self.hash.digest_length();
        if length > hash_len * 255 {
            panic!(
                "Cannot expand to more than 255 * {} = {} bytes using the specified hash function",
                hash_len,
                hash_len * 255
            );
        }

        if length == 0 {
            return vec![];
        }

        let blocks_needed = (length - 1) / hash_len + 1; // ceil
        let mut ret = Vec::with_capacity(blocks_needed * hash_len);
        let mut block = vec![];
        for i in 0..blocks_needed {
            block.extend_from_slice(info);
            block.push((i + 1) as u8);
            block = self.hash.digest(self.prk.as_slice(), block.as_slice());
            ret.extend(block.iter());
        }

        ret.truncate(length);
        return ret;
    }
}

#[derive(Copy, Clone)]
pub struct RingSha(pub ring::hmac::Algorithm);

impl Hash for RingSha {
    fn digest_length(&self) -> usize {
        self.0.digest_algorithm().output_len
    }

    fn digest(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let signature_key = ring::hmac::Key::new(self.0, key);
        ring::hmac::sign(&signature_key, msg).as_ref().into()
    }
}

pub struct OpensslSha(pub openssl::hash::MessageDigest);

impl OpensslSha {
    pub fn sha1() -> Self {
        OpensslSha(openssl::hash::MessageDigest::sha1())
    }

    pub fn sha256() -> Self {
        OpensslSha(openssl::hash::MessageDigest::sha256())
    }
}

impl Hash for OpensslSha {
    fn digest_length(&self) -> usize {
        self.0.size()
    }

    fn digest(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let key = openssl::pkey::PKey::hmac(key)
            .expect("Failed to construct openssl pkey");
        let mut signer = openssl::sign::Signer::new(self.0, &key)
            .expect("Failed to construct openssl signer");
        signer
            .update(msg)
            .expect("Failed to update message when signing");
        signer.sign_to_vec().expect("Failed to sign message")
    }
}

#[allow(dead_code)]
pub static SHA1_FOR_COMPATIBILITY: RingSha =
    RingSha(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);
#[allow(dead_code)]
pub static SHA256: RingSha = RingSha(ring::hmac::HMAC_SHA256);

#[cfg(test)]
#[rustfmt::skip::macros(crypto_array, crypto_vec)]
mod test {
    use super::*;

    #[test]
    fn test_derive_subkey_from_zero() {
        let hkdf = Hkdf::extract(None, b"key", SHA1_FOR_COMPATIBILITY);

        let subkey = hkdf.expand(b"ss-subkey", 32);
        assert_eq!(
            subkey,
            &crypto_array![
                0x84, 0xF6, 0x36, 0xC6, 0x88, 0x73, 0xCF, 0xEB,
                0x5B, 0xCF, 0xC1, 0x56, 0x94, 0x3F, 0x49, 0xE4,
                0xEF, 0x16, 0x68, 0xA9, 0xEE, 0x68, 0x37, 0xD7,
                0x5D, 0xEA, 0x19, 0x06, 0x20, 0x0E, 0x75, 0x0D
            ]
        );
    }

    #[test]
    fn test_derive_subkey_from_zero_openssl() {
        let hkdf = Hkdf::extract(None, b"key", OpensslSha::sha1());

        let subkey = hkdf.expand(b"ss-subkey", 32);
        assert_eq!(
            subkey,
            &crypto_array![
                0x84, 0xF6, 0x36, 0xC6, 0x88, 0x73, 0xCF, 0xEB,
                0x5B, 0xCF, 0xC1, 0x56, 0x94, 0x3F, 0x49, 0xE4,
                0xEF, 0x16, 0x68, 0xA9, 0xEE, 0x68, 0x37, 0xD7,
                0x5D, 0xEA, 0x19, 0x06, 0x20, 0x0E, 0x75, 0x0D
            ]
        );
    }

    // The salt is the iv derived from "sodiumoxide::crypto::aead::chacha20poly1305_ietf" by
    // EVP_BytesToKey() as implemented in Shadowsocks Python version. The input key material is the
    // key derived the same way.
    #[test]
    fn test_derive_subkey_from_salt() {
        let hkdf = Hkdf::extract(
            Some(&crypto_array![
                0xA9, 0xCA, 0xFD, 0x4F, 0x5F, 0xFD, 0x7A, 0x46,
                0x7F, 0xFE, 0x26, 0xA1, 0xE8, 0x0A, 0xC4, 0x4D,
                0xB0, 0x1F, 0x3C, 0x58, 0xCB, 0x4D, 0x17, 0xE0,
                0x3E, 0xC5, 0x2A, 0x05, 0x6D, 0x4B, 0xB9, 0x54
            ]),
            &crypto_array![
                0x4D, 0xC8, 0xA1, 0xA7, 0xBC, 0x06, 0x74, 0x4D,
                0x9C, 0x6B, 0x4F, 0xB3, 0x27, 0xFF, 0x52, 0x69,
                0x3C, 0x44, 0xF1, 0xBD, 0x94, 0xD2, 0x7D, 0xD4,
                0xD6, 0xE1, 0x90, 0xAF, 0x65, 0x71, 0x99, 0x7D
            ],
            SHA256,
        );

        let subkey = hkdf.expand(b"ss-subkey", 32);
        assert_eq!(
            subkey,
            &crypto_array![
                0xD4, 0xE4, 0x88, 0x52, 0xD8, 0x2B, 0x88, 0x6E,
                0x2F, 0x8F, 0x28, 0x68, 0x83, 0x56, 0x68, 0x69,
                0x0B, 0xFE, 0xB7, 0x55, 0xEE, 0xBD, 0x21, 0xCF,
                0x99, 0xBC, 0xEA, 0x88, 0xCC, 0xCF, 0x24, 0x40
            ],
        );
    }

    #[test]
    fn test_derive_subkey_from_salt_openssl() {
        let hkdf = Hkdf::extract(
            Some(&crypto_array![
                0xA9, 0xCA, 0xFD, 0x4F, 0x5F, 0xFD, 0x7A, 0x46,
                0x7F, 0xFE, 0x26, 0xA1, 0xE8, 0x0A, 0xC4, 0x4D,
                0xB0, 0x1F, 0x3C, 0x58, 0xCB, 0x4D, 0x17, 0xE0,
                0x3E, 0xC5, 0x2A, 0x05, 0x6D, 0x4B, 0xB9, 0x54,
            ]),
            &crypto_array![
                0x4D, 0xC8, 0xA1, 0xA7, 0xBC, 0x06, 0x74, 0x4D,
                0x9C, 0x6B, 0x4F, 0xB3, 0x27, 0xFF, 0x52, 0x69,
                0x3C, 0x44, 0xF1, 0xBD, 0x94, 0xD2, 0x7D, 0xD4,
                0xD6, 0xE1, 0x90, 0xAF, 0x65, 0x71, 0x99, 0x7D,
            ],
            OpensslSha::sha256(),
        );

        let subkey = hkdf.expand(b"ss-subkey", 32);
        assert_eq!(
            subkey,
            &crypto_array![
                0xD4, 0xE4, 0x88, 0x52, 0xD8, 0x2B, 0x88, 0x6E,
                0x2F, 0x8F, 0x28, 0x68, 0x83, 0x56, 0x68, 0x69,
                0x0B, 0xFE, 0xB7, 0x55, 0xEE, 0xBD, 0x21, 0xCF,
                0x99, 0xBC, 0xEA, 0x88, 0xCC, 0xCF, 0x24, 0x40
            ],
        );
    }
}
