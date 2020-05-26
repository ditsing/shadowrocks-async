use std::time::Duration;

use crate::crypto::{derive_master_key_compatible, derive_master_key_pbkdf2};
use crate::{CipherType, Result};

/// A structure that holds the information needed when servers are running.
#[derive(Clone)]
pub struct GlobalConfig {
    pub master_key: Vec<u8>,
    pub cipher_type: CipherType,
    pub timeout: Duration,
    #[allow(dead_code)]
    pub fast_open: bool,
    pub compatible_mode: bool,
}

impl GlobalConfig {
    pub fn build(
        password: &[u8],
        cipher_name: &str,
        timeout: Duration,
        fast_open: bool,
        compatible_mode: bool,
    ) -> Result<Self> {
        let cipher_type: CipherType = cipher_name.parse()?;
        let key_size = cipher_type.spec().key_size;
        let master_key = if compatible_mode {
            derive_master_key_compatible(password, key_size)?
        } else {
            derive_master_key_pbkdf2(password, &[], key_size)?
        };

        Ok(Self {
            master_key,
            cipher_type,
            timeout,
            fast_open,
            compatible_mode,
        })
    }
}
