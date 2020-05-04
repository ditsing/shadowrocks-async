extern crate log;
extern crate stderrlog;
extern crate tokio;

mod error;
mod shadow_server;
mod socks5_addr;
mod socks_server;
mod util;

#[cfg(test)]
mod test_utils;

use error::Error;
use std::env;

pub type Result<T> = std::result::Result<T, Error>;

fn choose_log_level() -> log::LevelFilter {
    if cfg!(debug_assertions) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    stderrlog::new()
        .module(module_path!())
        .timestamp(stderrlog::Timestamp::Microsecond)
        .verbosity(choose_log_level() as usize)
        .init()
        .unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let server = socks_server::SocksServer::create(
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                51980,
            ),
            "127.0.0.1:51986",
        )
        .await?;
        server.run().await
    } else {
        let server =
            shadow_server::ShadowServer::create(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                51986,
            ))
            .await?;
        server.run().await
    }
    Ok(())
}
