#[macro_use]
extern crate clap;
extern crate shadowrocks;

use shadowrocks::{socks_server, CipherType, Result};

pub mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    utils::log_init();

    let app = clap_app!(shadowrocks =>
        (version: "0.1")
        (author: "Jing Yang <ditsing@gmail.com>")
        (about: "Shadowsocks re-implemented in async rust.")
        (@arg config: -c [FILE] +takes_value display_order(1)
        "path to config file. See https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File")
        (@arg local_addr: -b +takes_value display_order(2) default_value("127.0.0.1") "local binding address")
        (@arg local_port: -l +takes_value display_order(3) default_value("1080") "local port")
        (@arg server_addr: -s +takes_value display_order(4) default_value("0.0.0.0") "server address")
        (@arg server_port: -p +takes_value display_order(5) default_value("8388") "server port")
        (@arg password: -k +takes_value display_order(6) "password")
        (@arg method: -m +takes_value display_order(7) default_value("aes-256-gcm") possible_values(CipherType::possible_ciphers()) "encryption method to use")

        (@arg timeout: -t +takes_value display_order(8) default_value("300") "timeout in seconds")
        // Quote to escape hyphen "-"
        (@arg fast_open: --("fast-open") display_order(9) "use TCP_FASTOPEN, requires Linux 3.7+")
        (@arg compatible_mode: --("compatible-mode") display_order(10) "keep compatible with Shadowsocks")
    );

    let matches = app.get_matches();

    let (global_config, local_socket_addr, server_socket_addr) =
        utils::parse_commandline_args(&matches)?;

    let server = socks_server::SocksServer::create(
        local_socket_addr,
        server_socket_addr,
        global_config,
    )
    .await?;
    server.run().await;

    Ok(())
}
