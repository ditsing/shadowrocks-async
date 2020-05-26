extern crate async_trait;
extern crate clap;
extern crate log;
extern crate openssl;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate stderrlog;
extern crate tokio;

// Don't move! macros defined in test_utils must be included first.
#[cfg(test)]
#[macro_use]
mod test_utils;

mod async_io;
mod crypto;
mod encrypted_stream;
mod error;
mod parsed_flags;
pub mod shadow_server;
mod socks5_addr;
pub mod socks_server;
pub mod utils;

use std::time::Duration;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub use shadow_server::ShadowServer;
pub use socks_server::SocksServer;

pub use crate::crypto::{
    derive_master_key_compatible, derive_master_key_pbkdf2, CipherType,
};

pub use parsed_flags::ParsedFlags;

#[derive(Clone)]
pub struct GlobalConfig {
    pub master_key: Vec<u8>,
    pub cipher_type: CipherType,
    pub timeout: Duration,
    #[allow(dead_code)]
    pub fast_open: bool,
    pub compatible_mode: bool,
}
