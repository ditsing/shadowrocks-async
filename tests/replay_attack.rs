extern crate shadowrocks;

use shadowrocks::utils::create_any_tcp_listener;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

// A local tcp server that writes 1209 to all incoming connections.
pub fn run_local_tcp_server() -> std::io::Result<SocketAddr> {
    let tcp_listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = tcp_listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in tcp_listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mask = 1209u16.to_be_bytes();
                    stream.write_all(&mask)?;
                    stream.flush()?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });
    Ok(local_addr)
}

// A middle man that records uploading traffic but discards downloading traffic.
pub fn run_middleman(
    incoming_server: TcpListener,
    outgoing: SocketAddr,
) -> std::io::Result<Vec<u8>> {
    println!("Running middleman");

    let mut ret = vec![];
    let mut outgoing_stream = TcpStream::connect(outgoing)?;
    println!("Middleman waiting for tcp connection.");
    let mut incoming_stream = incoming_server
        .incoming()
        .next()
        .expect("There should be at least one connection")?;

    let mut incoming_clone = incoming_stream.try_clone()?;
    let mut outgoing_clone = outgoing_stream.try_clone()?;
    // Proxying traffic from shadow server to socks server.
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(bytes) = outgoing_clone.read(&mut buf) {
            if bytes == 0 || incoming_clone.write_all(&buf[..bytes]).is_err() {
                break;
            }
        }
    });

    // Recording traffic from socks server to shadow server.
    let mut buf = [0u8; 8192];
    while let Ok(bytes) = incoming_stream.read(&mut buf) {
        if bytes == 0 {
            break;
        }

        let data = &buf[..bytes];
        ret.extend_from_slice(data);
        outgoing_stream.write_all(data)?;
        println!("Middleman received {} bytes", ret.len());
    }

    Ok(ret)
}

// Reply recorded data stream, and collect response.
pub fn replay(data: &[u8], outgoing: SocketAddr) -> std::io::Result<Vec<u8>> {
    println!("Running replay attack");

    let mut ret = vec![];
    let mut buf = [0u8; 8192];
    let mut outgoing_stream = TcpStream::connect(outgoing)?;
    outgoing_stream.write_all(data)?;

    println!("Replay attack for shadow server reply.");
    while let Ok(bytes) = outgoing_stream.read(&mut buf) {
        if bytes == 0 {
            break;
        }
        println!("Replay attack received reply {} bytes", bytes);
        ret.extend_from_slice(&buf[..bytes]);
    }
    println!("Replay attack completed.");

    Ok(ret)
}

fn run_replay_attack(compatible_mode: bool) -> std::io::Result<Vec<u8>> {
    let middleman_server = create_any_tcp_listener()?;
    let middleman_server_addr = middleman_server.local_addr()?;

    let shadow_tcp_listener = create_any_tcp_listener()?;
    let shadow_server_addr = shadow_tcp_listener.local_addr()?;

    let socks_tcp_listener = create_any_tcp_listener()?;
    let socks_server_addr = socks_tcp_listener.local_addr()?;

    let global_config = shadowrocks::GlobalConfig {
        master_key: vec![1u8; 32],
        cipher_type: shadowrocks::CipherType::Chacha20IetfPoly1305,
        timeout: std::time::Duration::from_secs(300),
        fast_open: false,
        compatible_mode,
    };

    println!("Starting tokio runtime and servers");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Should not fail when creating a runtime.");
        // Note servers are not properly terminated.
        rt.block_on(async move {
            socks_tcp_listener.set_nonblocking(true).unwrap();
            let socks_server = shadowrocks::SocksServer::create_from_std(
                socks_tcp_listener,
                middleman_server_addr,
                global_config.clone(),
            )
            .expect("Creating server should not fail.");

            shadow_tcp_listener.set_nonblocking(true).unwrap();
            let shadow_server = shadowrocks::ShadowServer::create_from_std(
                shadow_tcp_listener,
                #[allow(clippy::redundant_clone)]
                global_config.clone(),
            )
            .expect("Creating server should not fail.");
            tokio::join!(socks_server.run(), shadow_server.run());
        });
    });

    let fake_target = run_local_tcp_server()?;

    println!("Connecting to socks server");
    let mut socks5_client = TcpStream::connect(socks_server_addr)?;
    socks5_client.set_nonblocking(true)?;
    // Send socks5 command "connect to fake target".
    socks5_client
        .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1])?;
    socks5_client.write_all(&fake_target.port().to_be_bytes())?;
    socks5_client.flush()?;
    socks5_client.shutdown(std::net::Shutdown::Both)?;

    let data = run_middleman(middleman_server, shadow_server_addr)?;
    let result = replay(&data, shadow_server_addr)?;

    Ok(result)
}

#[test]
fn test_replay_attack_compatible() -> std::io::Result<()> {
    let result = run_replay_attack(true)?;

    // Replay attack worked, server returned more than just salt.
    assert!(result.len() > 32);

    Ok(())
}

#[test]
fn test_replay_attack() -> std::io::Result<()> {
    let result = run_replay_attack(false)?;

    // Replay attack failed, server returned only salt.
    assert!(result.len() <= 32);

    Ok(())
}
