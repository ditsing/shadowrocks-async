extern crate async_trait;
extern crate base64;
extern crate clap;
extern crate log;
extern crate openssl;
extern crate percent_encoding;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate tokio;
extern crate url;

// Don't move! macros defined in test_utils must be included first.
#[cfg(test)]
#[macro_use]
mod test_utils;

mod async_io;
mod crypto;
mod encrypted_stream;
mod error;
mod global_config;
mod parsed_flags;
mod parsed_server_url;
pub mod shadow_server;
mod socks5_addr;
pub mod socks_server;
pub mod utils;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub use crypto::CipherType;
pub use global_config::GlobalConfig;
pub use parsed_flags::ParsedFlags;
pub use parsed_server_url::ParsedServerUrl;
pub use shadow_server::ShadowServer;
pub use socks_server::SocksServer;
