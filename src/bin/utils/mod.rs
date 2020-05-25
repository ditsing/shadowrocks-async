/// A module that helps building a binary: commandline flags, log levels etc.
extern crate stderrlog;

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use shadowrocks::{GlobalConfig, ParsedFlags, Result};

fn choose_log_level() -> log::LevelFilter {
    if cfg!(debug_assertions) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    }
}

pub fn log_init() {
    stderrlog::new()
        .module("shadowrocks")
        .timestamp(stderrlog::Timestamp::Microsecond)
        .verbosity(choose_log_level() as usize)
        .init()
        .unwrap();
}

#[allow(unused)]
pub fn parse_commandline_args(
    matches: &clap::ArgMatches,
) -> Result<(GlobalConfig, SocketAddr, SocketAddr)> {
    let parsed_flags = matches
        .value_of("config")
        .map(ParsedFlags::from_config_file)
        .transpose()?;
    let parsed_flags = parsed_flags.as_ref();

    let server_addr = matches.value_of("server_addr").unwrap_or("0.0.0.0");
    let server_port: u16 = matches
        .value_of("server_port")
        .unwrap_or("8388")
        .parse()
        .expect("Server port must be a valid number.");
    let server_socket_addr = parsed_flags
        .and_then(ParsedFlags::server_addr)
        .unwrap_or((server_addr, server_port))
        .to_socket_addrs()?
        .next()
        .expect("Expecting a valid server address and port.");

    let local_addr = matches.value_of("local_addr").unwrap_or("127.0.0.1");
    let local_port: u16 = matches
        .value_of("local_port")
        .unwrap_or("1080")
        .parse()
        .expect("Local port must be a valid number.");
    let local_socket_addr = parsed_flags
        .and_then(ParsedFlags::local_addr)
        .unwrap_or((local_addr, local_port))
        .to_socket_addrs()?
        .next()
        .expect("Expecting a valid server address and port.");

    let password = parsed_flags.map(|c| c.password()).unwrap_or_else(|| {
        matches
            .value_of("password")
            .expect("Password is required.")
            .as_bytes()
    });

    let cipher_name = parsed_flags
        .and_then(|c| c.encryption_method())
        .or_else(|| matches.value_of("method"))
        .unwrap_or("aes-256-gcm");

    let timeout = matches
        .value_of("timeout")
        .unwrap_or("300")
        .parse()
        .map(Duration::from_secs)
        .expect("Timeout must be a valid integer.");

    let fast_open = parsed_flags
        .and_then(|c| c.fast_open())
        .unwrap_or_else(|| matches.is_present("fast_open"));
    let compatible_mode = matches.is_present("compatible-mode");

    let global_config = GlobalConfig::build(
        password,
        cipher_name,
        timeout,
        fast_open,
        compatible_mode,
    )?;

    Ok((global_config, local_socket_addr, server_socket_addr))
}
