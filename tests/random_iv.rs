extern crate shadowrocks;

use shadowrocks::utils::create_any_tcp_listener;
use std::io::Read;
use std::net::TcpStream;

const SERVER_COUNT: u32 = 10;
const IV_ROUNDS: u32 = 10;
fn run_random_iv_test(compatible_mode: bool) -> std::io::Result<()> {
    let global_config = shadowrocks::GlobalConfig {
        master_key: vec![1u8; 32],
        cipher_type: shadowrocks::CipherType::Chacha20IetfPoly1305,
        timeout: std::time::Duration::from_secs(300),
        fast_open: false,
        compatible_mode,
    };

    let mut addrs = vec![];
    #[allow(clippy::same_item_push)]
    for _ in 0..SERVER_COUNT {
        let shadow_tcp_listener = create_any_tcp_listener()?;
        let addr = shadow_tcp_listener.local_addr()?;
        let global_config = global_config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Should not fail when creating a runtime.");
            let shadow_server = rt.block_on(async move {
                shadow_tcp_listener.set_nonblocking(true).unwrap();
                shadowrocks::ShadowServer::create_from_std(
                    shadow_tcp_listener,
                    global_config,
                )
                .expect("Creating shadow server should not fail")
            });
            rt.block_on(shadow_server.run());
        });

        addrs.push(addr);
    }

    let mut collected_ivs = vec![];
    for _ in 0..IV_ROUNDS {
        for addr in &addrs {
            let mut tcp_stream = TcpStream::connect(addr)?;
            let mut buf = vec![0u8; 32];
            tcp_stream.read_exact(&mut buf)?;
            collected_ivs.push(buf);
        }
    }
    for addr in &addrs {
        for _ in 0..IV_ROUNDS {
            let mut tcp_stream = TcpStream::connect(addr)?;
            let mut buf = vec![0u8; 32];
            tcp_stream.read_exact(&mut buf)?;
            collected_ivs.push(buf);
        }
    }

    collected_ivs.sort();
    let before_len = collected_ivs.len();
    collected_ivs.dedup();
    let after_len = collected_ivs.len();

    assert_eq!(before_len, after_len);
    Ok(())
}

/// A test to verify that IVs are truly random, in compatible mode.
#[test]
fn test_random_iv_compatible() -> std::io::Result<()> {
    run_random_iv_test(true)
}

/// A test to verify that IVs are truly random.
#[test]
fn test_random_iv() -> std::io::Result<()> {
    run_random_iv_test(false)
}
