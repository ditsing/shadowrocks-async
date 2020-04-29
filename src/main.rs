extern crate log;
extern crate tokio;

mod error;
mod socks_server;
mod socks5_addr;
mod util;

use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

fn main() {
}
