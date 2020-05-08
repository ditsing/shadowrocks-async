use std::net::SocketAddr;

use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;

use crate::{Error, Result};
use crate::encrypted_stream::EncryptedStream;
use crate::socks5_addr::Socks5Addr;

pub struct ShadowServer {
    tcp_listener: Option<TcpListener>,
}

impl ShadowServer {
    pub async fn create(addr: SocketAddr) -> Result<Self> {
        info!("Creating shadow server ...");
        Ok(Self {
            tcp_listener: Some(TcpListener::bind(addr).await?),
        })
    }

    async fn serve_shadow_stream(&mut self, stream: TcpStream) -> Result<()> {
        info!("Serving shadow stream ...");
        let local_addr = stream.local_addr()?;
        let peer_addr = stream.peer_addr()?;

        let mut encrypted_stream = EncryptedStream::establish(stream).await?;

        let target_addr = Socks5Addr::read_and_parse_address(&mut encrypted_stream).await?;

        debug!("Processing request from {} to {:?}", peer_addr, target_addr);

        info!("Resolving target IP address ...");
        info!("Connecting to target address ...");
        let target_stream = match &target_addr {
            Socks5Addr::Domain(domain_buf, port) => {
                let domain_str_result = std::str::from_utf8(&domain_buf);
                let domain_str = match domain_str_result {
                    Ok(domain_str) => domain_str,
                    Err(e) => return Err(Error::MalformedDomainString(domain_buf.to_owned(), e)),
                };
                info!("Looking up host ...");
                TcpStream::connect((domain_str, *port)).await?
            }
            Socks5Addr::V4(socket_addr_v4) => {
                TcpStream::connect(socket_addr_v4).await?
            }
            Socks5Addr::V6(socket_addr_v6) => {
                TcpStream::connect(socket_addr_v6).await?
            }
        };

        info!("Creating relay ...");
        crate::async_io::proxy(encrypted_stream, target_stream, target_addr);
        info!("Relay created on port {}.", local_addr.port());

        Ok(())
    }

    pub async fn run(mut self) {
        let mut tcp_listener =
            self.tcp_listener.take().expect("Expecting an initialized tcp server");
        info!("Running shadow server loop ...");
        while let Some(stream) = tcp_listener.next().await {
            match stream {
                Ok(stream) => {
                    info!("New connection");
                    let response = self.serve_shadow_stream(stream).await;
                    if let Err(e) = response {
                        error!("Error serving shadow client: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error accepting shadow connection: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use crate::test_utils::local_tcp_server::run_local_tcp_server;

    use super::*;

    const SOCKS_SERVER_ADDR: &str = "127.0.0.1:0";
    const DOMAIN_ADDR: &str = "localhost";

    fn start_and_connect_to_server() -> Result<TcpStream> {
        let local_socket_addr: SocketAddr =
            SOCKS_SERVER_ADDR.parse().expect("Parsing should not fail.");
        let tcp_listener = TcpListener::bind(local_socket_addr)?;
        let server_addr = tcp_listener.local_addr()?;
        std::thread::spawn(move || {
            let mut rt = tokio::runtime::Runtime::new()
                .expect("Shout not error when creating a runtime.");
            rt.block_on(async {
                // The wrapping part must be done inside a tokio runtime environment.
                let server = ShadowServer {
                    tcp_listener: Some(tokio::net::TcpListener::from_std(tcp_listener).unwrap()),
                };
                server.run().await
            });
        });
        Ok(TcpStream::connect(server_addr)?)
    }

    #[test]
    fn test_shadow_stream() -> Result<()> {
        let (local_tcp_server_addr, _tcp_server_running) = run_local_tcp_server()?;
        let socks5_addr = match local_tcp_server_addr {
            SocketAddr::V4(socket_addr_v4) => Socks5Addr::V4(socket_addr_v4),
            SocketAddr::V6(socket_addr_v6) => Socks5Addr::V6(socket_addr_v6),
        };

        let mut stream = start_and_connect_to_server()?;
        stream.write_all(&socks5_addr.bytes())?;

        stream.write_all(&[0x07, 0xC6])?;
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x04, 0xB9, 0x00, 0x00, 0x00, 0x01]);

        let mut stream = TcpStream::connect(stream.peer_addr()?)?;
        stream.write_all(&socks5_addr.bytes())?;

        stream.write_all(&[0x07, 0xC6])?;
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x04, 0xB9, 0x00, 0x00, 0x00, 0x02]);
        Ok(())
    }

    #[test]
    fn test_shadow_stream_domain() -> Result<()> {
        let (local_tcp_server_addr, _tcp_server_running) = run_local_tcp_server()?;
        let mut stream = start_and_connect_to_server()?;
        stream.write_all(&[0x03, 0x09])?;
        stream.write_all(DOMAIN_ADDR.as_bytes())?;
        stream.write_all(&local_tcp_server_addr.port().to_be_bytes())?;

        stream.write_all(&[0x07, 0xC6])?;
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x04, 0xB9, 0x00, 0x00, 0x00, 0x01]);

        let mut stream = TcpStream::connect(stream.peer_addr()?)?;
        stream.write_all(&[0x03, 0x09])?;
        stream.write_all(DOMAIN_ADDR.as_bytes())?;
        stream.write_all(&local_tcp_server_addr.port().to_be_bytes())?;

        stream.write_all(&[0x07, 0xC6])?;
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x04, 0xB9, 0x00, 0x00, 0x00, 0x02]);
        Ok(())
    }

    #[test]
    fn test_shadow_stream_malformed_domain_string() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        stream.write_all(&[0x03, 0x01, 0xFF, 0x00, 0x00])?;

        let mut buf = [0u8; 1];
        let result = stream.read_exact(&mut buf);
        if let Err(_) = result {
            // expected.
        } else {
            panic!("Server should not send response or accept writes.");
        }
        Ok(())
    }

    #[test]
    fn test_shadow_stream_error() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        stream.write_all(&[0x01, 127, 0, 0, 1, 0, 80])?;

        let mut buf = [0u8; 1];
        let result = stream.read_exact(&mut buf);
        if let Err(_) = result {
            // expected.
        } else {
            panic!("Server should not send response or accept writes.");
        }
        Ok(())
    }
}
