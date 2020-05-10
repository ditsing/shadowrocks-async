#![cfg(feature = "ring-crypto")]
pub struct KeyType(pub usize);

impl ring::hkdf::KeyType for KeyType {
    fn len(&self) -> usize {
        self.0
    }
}
