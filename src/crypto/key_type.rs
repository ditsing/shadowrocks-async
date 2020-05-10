#![cfg(feature = "ring-hkdf")]
pub struct KeyType(pub usize);

impl ring::hkdf::KeyType for KeyType {
    fn len(&self) -> usize {
        self.0
    }
}
