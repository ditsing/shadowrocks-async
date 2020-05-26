extern crate shadowrocks;

use std::net::ToSocketAddrs;
use std::time::Duration;

use shadowrocks::{
    derive_master_key_compatible, derive_master_key_pbkdf2, lookup_cipher,
    parse_config_file, shadow_server, socks_server, GlobalConfig, ParsedFlags,
    Result,
};

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

    let app = clap::App::new("shadowrocks")
        .version("0.1")
        .author("Jing Yang <ditsing@gmail.com>")
        .about("Shadowsocks, a fast tunnel proxy that helps you bypass firewalls, re-implemented in rust.")
        .before_help("You can supply configurations via either config file or command line arguments.")
        .args_from_usage("
            -s [SERVER_ADDR]         'server address'
            -p [SERVER_PORT]         'server port, default: 8388'
            -b [LOCAL_ADDR]          'local binding address, default: 127.0.0.1'
            -l [LOCAL_PORT]          'local port, default: 1080'
            -k [PASSWORD]            'password'
            -m [METHOD]              'encryption method to use, default: aes-256-gcm. Other valid values are: aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305'
            -t [TIMEOUT]             'timeout in seconds, default: 300'
            -c [CONFIG_FILE]         'path to config file. See https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File'


            --fast-open              'use TCP_FASTOPEN, requires Linux 3.7+, default: false'
            --compatible-mode        'keep compatible with Shadowsocks in encryption-related areas, default: false'
            --shadow                 'whether to run shadow server or local server, default: false'
        ")
        .after_help("Homepage: <https://github.com/ditsing/shadowrocks>");
    let matches = app.get_matches();

    let parsed_flags =
        matches.value_of("c").map(parse_config_file).transpose()?;
    let parsed_flags = parsed_flags.as_ref();
    let password = parsed_flags.map(|c| c.password()).unwrap_or_else(|| {
        matches
            .value_of("k")
            .expect("Password is required.")
            .as_bytes()
    });

    let server_addr = matches.value_of("s").unwrap_or("0.0.0.0");
    let server_port: u16 = matches
        .value_of("p")
        .unwrap_or("8388")
        .parse()
        .expect("Server port must be a valid number.");
    let server_socket_addr = parsed_flags
        .and_then(ParsedFlags::server_addr)
        .unwrap_or((server_addr, server_port))
        .to_socket_addrs()?
        .next()
        .expect("Expecting a valid server address and port.");

    let local_addr = matches.value_of("b").unwrap_or("127.0.0.1");
    let local_port: u16 = matches
        .value_of("l")
        .unwrap_or("1080")
        .parse()
        .expect("Local port must be a valid number.");
    let local_socket_addr = parsed_flags
        .and_then(ParsedFlags::local_addr)
        .unwrap_or((local_addr, local_port))
        .to_socket_addrs()?
        .next()
        .expect("Expecting a valid server address and port.");

    let is_shadow_server = matches.is_present("shadow");

    let cipher_name = matches.value_of("m").unwrap_or("aes-256-gcm");
    let cipher_name = parsed_flags
        .and_then(|c| c.encryption_method())
        .unwrap_or(cipher_name);
    let cipher_type = lookup_cipher(cipher_name)?;
    let timeout = matches
        .value_of("t")
        .unwrap_or("300")
        .parse()
        .map(Duration::from_secs)
        .expect("Timeout must be a valid integer.");
    let fast_open = matches.is_present("fast_open");
    let fast_open = parsed_flags
        .and_then(|c| c.fast_open())
        .unwrap_or(fast_open);
    let compatible_mode = matches.is_present("compatible-mode");

    let global_config = GlobalConfig {
        master_key: if compatible_mode {
            derive_master_key_compatible(password, cipher_type.spec().key_size)?
        } else {
            derive_master_key_pbkdf2(
                password,
                &[],
                cipher_type.spec().key_size,
            )?
        },
        cipher_type,
        timeout,
        fast_open,
        compatible_mode,
    };

    if is_shadow_server {
        let server = shadow_server::ShadowServer::create(
            server_socket_addr,
            global_config,
        )
        .await?;
        server.run().await
    } else {
        let server = socks_server::SocksServer::create(
            local_socket_addr,
            server_socket_addr,
            global_config,
        )
        .await?;
        server.run().await
    }
    Ok(())
}
