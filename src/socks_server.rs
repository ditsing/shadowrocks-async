use std::io::ErrorKind;
use std::net::{Shutdown, SocketAddr, ToSocketAddrs};

use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;

use crate::async_io::{AsyncReadTrait, AsyncWriteTrait};
use crate::encrypted_stream::EncryptedStream;
use crate::socks5_addr::{Socks5Addr, Socks5AddrType};
use crate::{Error, GlobalConfig, Result};

pub struct SocksServer {
    remote_addr: SocketAddr,
    tcp_listener: TcpListener,

    global_config: GlobalConfig,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    // NO AUTHENTICATION REQUIRED
    NoAuthenticationRequired = 0x00,
    // GSSAPI
    Gssapi = 0x01,
    // USERNAME/PASSWORD
    UsernamePassword = 0x02,
    // IANA ASSIGNED
    IanaAssigned = 0x03,
    // PRIVATE METHODS
    PrivateMethods = 0x80,
    // NO ACCEPTABLE METHODS
    NoAcceptableMethods = 0xFF,
}

impl From<u8> for Method {
    fn from(method: u8) -> Self {
        match method {
            0x00 => Method::NoAuthenticationRequired,
            0x01 => Method::Gssapi,
            0x02 => Method::UsernamePassword,
            0x03..=0x7F => Method::IanaAssigned,
            0x80..=0xFE => Method::PrivateMethods,
            0xFF => Method::NoAcceptableMethods,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[repr(u8)]
#[derive(Debug)]
enum ReplyStatus {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl SocksServer {
    const SOCKET_VERSION: u8 = 0x05u8;
    const RSV: u8 = 0x00u8;

    pub async fn create<A: ToSocketAddrs>(
        addr: SocketAddr,
        remote: A,
        global_config: GlobalConfig,
    ) -> Result<Self> {
        info!("Creating SOCKS5 server ...");
        info!("Starting socks server at address {} ...", addr);
        Ok(Self {
            remote_addr: remote
                .to_socket_addrs()?
                .next()
                .expect("Expecting a valid server address and port as remote"),
            tcp_listener: TcpListener::bind(addr).await?,

            global_config,
        })
    }

    fn check_socks_version(version: u8) -> Result<()> {
        if version != Self::SOCKET_VERSION {
            error!("Failed: socks version does not match {:#02X?}", version);
            Err(Error::UnsupportedSocksVersion(version))
        } else {
            Ok(())
        }
    }

    fn check_rsv(rsv: u8) -> Result<()> {
        if rsv != Self::RSV {
            error!("Failed: reserved bit does not match {:#02X?}", rsv);
            Err(Error::UnexpectedReservedBit(rsv))
        } else {
            Ok(())
        }
    }

    async fn read_and_parse_first_request(
        stream: &mut (impl AsyncReadTrait + std::marker::Unpin),
    ) -> Result<Vec<Method>> {
        info!("SOCKS5 handshaking ...");
        // The first two bytes contains version and number of methods.
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        // Confirm socks version.
        Self::check_socks_version(buf[0])?;

        // The following `nmethods` bytes contain all acceptable methods.
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        debug!("Expecting {} following bytes", nmethods);
        info!("Reading acceptable auth methods ...");
        stream.read_exact(&mut methods.as_mut_slice()).await?;

        // Extract a list of all methods
        let mut ret = Vec::with_capacity(nmethods);
        for method in methods {
            ret.push(Method::from(method));
        }
        info!("Acceptable auth methods processed.");
        Ok(ret)
    }

    async fn read_and_parse_command_request(
        stream: &mut (impl AsyncReadTrait + std::marker::Unpin),
    ) -> Result<Option<Command>> {
        info!("Reading command request and rsv ...");
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await?;

        // Confirm socks version.
        Self::check_socks_version(buf[0])?;
        // Extract CMD.
        let cmd_byte = buf[1];
        let cmd = match cmd_byte {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => {
                error!("Unrecognized socks command {}", cmd_byte);
                return Ok(None);
            }
        };
        debug_assert_eq!(cmd_byte, cmd as u8);

        Self::check_rsv(buf[2])?;

        Ok(Some(cmd))
    }

    async fn serve_socks5_stream(
        &mut self,
        mut stream: TcpStream,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let available_methods =
            Self::read_and_parse_first_request(&mut stream).await?;
        let method =
            if available_methods.contains(&Method::NoAuthenticationRequired) {
                Method::NoAuthenticationRequired
            } else {
                Method::NoAcceptableMethods
            };
        info!("Agreed on auth method {:#?}", method);
        stream
            .write_all(&[Self::SOCKET_VERSION, method as u8])
            .await?;

        // Expecting a request with command.
        let cmd_option =
            Self::read_and_parse_command_request(&mut stream).await?;
        let cmd = match cmd_option {
            Some(cmd) => cmd,
            None => {
                stream
                    .write_all(&[
                        Self::SOCKET_VERSION,
                        ReplyStatus::CommandNotSupported as u8,
                        Self::RSV,
                    ])
                    .await?;
                return Ok(());
            }
        };

        let target_addr_result =
            Socks5Addr::read_and_parse_address(&mut stream).await;
        let target_addr = match target_addr_result {
            Ok(target_addr) => target_addr,
            Err(Error::UnsupportedAddressType(_cmd)) => {
                stream
                    .write_all(&[
                        Self::SOCKET_VERSION,
                        ReplyStatus::AddressTypeNotSupported as u8,
                        Self::RSV,
                    ])
                    .await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        debug!("Executing command {:#?} to target {:?}", cmd, target_addr);

        match cmd {
            Command::Connect => {
                // Note the order of operation:
                // 1. Create a connection to the target IP.
                // 2. Notify the client that a connection has been created, or return various
                // errors, e.g. network unreachable, connection not allowed, host not found and
                // connection refused.
                // 3. Save the relay in the map.
                info!("Connecting to remote ...");
                let remote_stream =
                    TcpStream::connect(remote_addr).await.map_err(|e| {
                        // Handle the error when connecting to the shadow server.
                        // A traditional socks proxy returns error when connecting to the target
                        // address. As a local proxy that relies on the remote shadow server to connect
                        // to the target, we don't know what the error is at this time. The shadow
                        // server does not tell us if a website is found or connection is refused.
                        //
                        // The only thing we know about, is the error connecting to the remote server.
                        // Thus that status is used in the "Reply Status" bit of the reply message.
                        let socks5_error = match e.kind() {
                            // Technically we should abort if permission is denied when making a
                            // connection. But we at least should let the client know.
                            ErrorKind::PermissionDenied => {
                                ReplyStatus::ConnectionNotAllowed
                            }
                            ErrorKind::NotConnected => {
                                ReplyStatus::NetworkUnreachable
                            }
                            ErrorKind::NotFound => ReplyStatus::HostUnreachable,
                            ErrorKind::ConnectionRefused => {
                                ReplyStatus::ConnectionRefused
                            }
                            ErrorKind::TimedOut => ReplyStatus::TtlExpired,
                            _ => ReplyStatus::GeneralFailure,
                        };
                        error!("Error connecting to remote: {}", e);
                        socks5_error
                    });
                let remote_stream = match remote_stream {
                    Ok(remote_stream) => remote_stream,
                    Err(reply_status) => {
                        #[rustfmt::skip]
                        let error_reply: [u8; 10] = [
                            Self::SOCKET_VERSION,
                            reply_status as u8,
                            Self::RSV,
                            Socks5AddrType::V4 as u8,
                            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                        ];

                        stream.write_all(&error_reply).await?;
                        return Ok(());
                    }
                };

                let local_to_remote_port = remote_stream.local_addr()?.port();
                let mut remote_encrypted_stream = EncryptedStream::establish(
                    remote_stream,
                    self.global_config.master_key.as_slice(),
                    self.global_config.cipher_type,
                )
                .await?;

                // Encryption not implemented.
                info!("Setting shadow address on remote ...");
                remote_encrypted_stream
                    .write_all(&target_addr.bytes())
                    .await?;

                #[rustfmt::skip]
                stream
                    .write_all(&[
                        Self::SOCKET_VERSION,
                        ReplyStatus::Succeeded as u8,
                        Self::RSV,
                        // RFC 1928 requires this address to be a valid address that the client is
                        // expected to connect to. In practise most client and server implementations
                        // only support re-using the existing connection.
                        // All zeros indicate that the client is expected to use the current TCP
                        // connection to send requests to be relayed.
                        Socks5AddrType::V4 as u8,
                        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                    ])
                    .await?;

                info!("Creating connection relay ...");
                crate::async_io::proxy(
                    stream,
                    remote_encrypted_stream,
                    target_addr,
                );
                info!("Relay created on port {}", local_to_remote_port);
            }
            _ => {
                #[rustfmt::skip]
                let unsupported_reply: [u8; 10] = [
                    Self::SOCKET_VERSION,
                    ReplyStatus::CommandNotSupported as u8,
                    Self::RSV,
                    Socks5AddrType::V4 as u8,
                    0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                ];

                stream.write_all(&unsupported_reply).await?;
                info!("Closing connection");
                stream.shutdown(Shutdown::Both)?;
                info!("Connection closed.");
            }
        }
        Ok(())
    }

    pub async fn run(mut self) {
        info!("Running socks server loop ...");
        while let Some(stream) = self.tcp_listener.next().await {
            match stream {
                Ok(stream) => {
                    info!("New connection");
                    let response = self
                        .serve_socks5_stream(stream, self.remote_addr.clone())
                        .await;
                    if let Err(e) = response {
                        error!("Error serving client: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    use crate::crypto::CipherType;
    use crate::test_utils::local_tcp_server::run_local_tcp_server;
    use crate::test_utils::ready_buf::ReadyBuf;

    use super::*;

    const DEFAULT_REMOTE_ADDR: &str = "127.0.0.1:80";
    const SOCKS_SERVER_ADDR: &str = "127.0.0.1:0";

    fn start_and_connect_to_server() -> Result<TcpStream> {
        start_and_connect_to_server_remote(
            DEFAULT_REMOTE_ADDR
                .parse()
                .expect("Parsing should not fail"),
        )
    }

    fn start_and_connect_to_server_remote(
        remote_addr: SocketAddr,
    ) -> Result<TcpStream> {
        let local_socket_addr: SocketAddr =
            SOCKS_SERVER_ADDR.parse().expect("Parsing should not fail.");
        let tcp_listener = TcpListener::bind(local_socket_addr)?;
        let server_addr = tcp_listener.local_addr()?;
        std::thread::spawn(move || {
            let mut rt = tokio::runtime::Runtime::new()
                .expect("Shout not error when creating a runtime.");
            rt.block_on(async {
                // The wrapping part must be done inside a tokio runtime environment.
                let server = SocksServer {
                    remote_addr,
                    tcp_listener: tokio::net::TcpListener::from_std(
                        tcp_listener,
                    )
                    .expect("Creating tcp listener should not fail"),
                    global_config: GlobalConfig {
                        master_key: vec![],
                        cipher_type: CipherType::None,
                        timeout: Duration::from_secs(1),
                        fast_open: false,
                        compatible_mode: false,
                    },
                };
                server.run().await
            });
        });
        Ok(TcpStream::connect(server_addr)?)
    }

    #[tokio::test]
    async fn test_socks5_handshake_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x05, 0x02, 0x00, 0x80]]);
        let methods =
            SocksServer::read_and_parse_first_request(&mut ready_buf).await?;
        assert_eq!(
            methods,
            vec![Method::NoAuthenticationRequired, Method::PrivateMethods]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_handshake_version_mismatch_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x04, 0x00]]);
        let result =
            SocksServer::read_and_parse_first_request(&mut ready_buf).await;
        if let Err(Error::UnsupportedSocksVersion(v)) = result {
            assert_eq!(v, 0x04);
        } else {
            panic!("Should return error UnsupportedSocksVersion = 0x04");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_handshake_no_methods_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x05, 0x00]]);
        let methods =
            SocksServer::read_and_parse_first_request(&mut ready_buf).await?;
        assert_eq!(methods, vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_command_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x05, 0x02, 0x00]]);
        let command =
            SocksServer::read_and_parse_command_request(&mut ready_buf).await?;
        assert_eq!(command, Some(Command::Bind));
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_command_version_mismatch_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x04, 0x02, 0x00]]);
        let result =
            SocksServer::read_and_parse_command_request(&mut ready_buf).await;
        if let Err(Error::UnsupportedSocksVersion(v)) = result {
            assert_eq!(v, 0x04);
        } else {
            panic!("Should return error UnsupportedSocksVersion = 0x04");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_command_none_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x05, 0x04, 0x00]]);
        let cmd =
            SocksServer::read_and_parse_command_request(&mut ready_buf).await?;
        assert!(cmd.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_command_rsv_async() -> Result<()> {
        let mut ready_buf = ReadyBuf::make(&[&[0x05, 0x03, 0x01]]);
        let result =
            SocksServer::read_and_parse_command_request(&mut ready_buf).await;
        if let Err(Error::UnexpectedReservedBit(v)) = result {
            assert_eq!(v, 0x01);
        } else {
            panic!("Should return error UnexpectedReservedBit = 0x01");
        }
        Ok(())
    }

    // Not running async tests any more, since serve_socks5_stream() takes a TcpStream, which is
    // Not straight forward to mock.
    #[test]
    fn test_socks5_no_auth_methods() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // 0x08 = Private auth method.
        stream.write_all(&[0x05, 0x01, 0x08])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0xFF]); // Socks version 5, no acceptable methods.

        Ok(())
    }

    #[test]
    fn test_socks5_agreed_auth_methods() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // 0x08 = Private auth method.
        // 0x00 = No auth required.
        stream.write_all(&[0x05, 0x02, 0x08, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        Ok(())
    }

    #[test]
    fn test_socks5_command_not_supported() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x04
        stream.write_all(&[0x05, 0x04, 0x00])?;
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x07, 0x00]);

        Ok(())
    }

    #[test]
    fn test_socks5_command_address_not_supported() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x01 Connect, Address = 0x02
        stream.write_all(&[0x05, 0x01, 0x00, 0x02])?;
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x08, 0x00]);

        Ok(())
    }

    #[test]
    fn test_socks5_command_connect() -> Result<()> {
        let (local_tcp_server_addr, _tcp_server_running) =
            run_local_tcp_server()?;
        let mut stream =
            start_and_connect_to_server_remote(local_tcp_server_addr)?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x01 Connect, Address = 0x01 IPv4 127.0.0.1:80
        stream.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])?;
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf)?;
        assert_eq!(
            buf,
            [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        Ok(())
    }

    #[test]
    fn test_socks5_command_other() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x02 Bind, Address = 0x03 Domain with port "@:00"
        stream.write_all(&[0x05, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00, 0x00])?;
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf)?;
        assert_eq!(
            buf,
            [0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        Ok(())
    }

    #[test]
    fn test_socks5_command_connect_failure() -> Result<()> {
        let mut stream = start_and_connect_to_server()?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x01 Connect, Address = 0x01 IPv4 127.0.0.1:80
        stream.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])?;
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf)?;
        // Connection refused.
        assert_eq!(
            buf,
            [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        Ok(())
    }

    #[test]
    fn test_socks5_command_connect_proxy() -> Result<()> {
        let (local_tcp_server_addr, _tcp_server_running) =
            run_local_tcp_server()?;
        let socks5_addr = match local_tcp_server_addr {
            SocketAddr::V4(socket_addr_v4) => Socks5Addr::V4(socket_addr_v4),
            SocketAddr::V6(socket_addr_v6) => Socks5Addr::V6(socket_addr_v6),
        };

        let mut stream =
            start_and_connect_to_server_remote(local_tcp_server_addr)?;
        // Handshake.
        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x05, 0x00]); // Socks version 5, no auth required.

        // Command = 0x01 Connect, Address = local_tcp_server_addr
        stream.write_all(&[0x05, 0x01, 0x00])?;
        stream.write_all(&socks5_addr.bytes())?;
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf)?;
        assert_eq!(
            buf,
            [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        assert_eq!(buf, [0x00, 0x01]);

        // Allow the connection to be dropped by server.
        stream.write_all(&[])?;

        Ok(())
    }
}
