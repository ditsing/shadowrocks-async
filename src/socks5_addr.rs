use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use log::{debug, error, info};

use crate::{Error, Result};
use crate::async_io_traits::AsyncReadTrait;

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Socks5Addr {
    V4(SocketAddrV4),
    Domain(Vec<u8>, u16),
    V6(SocketAddrV6),
}

#[repr(u8)]
#[derive(Debug)]
pub enum Socks5AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl Socks5Addr {
    pub fn bytes(&self) -> Vec<u8> {
        let mut ret = vec![];
        match self {
            Socks5Addr::V4(socket_addr_v4) => {
                ret.push(Socks5AddrType::V4 as u8);
                socket_addr_v4.ip().octets().iter()
                    .for_each(|byte| ret.push(*byte));
                socket_addr_v4.port()
                    .to_be_bytes()
                    .iter()
                    .for_each(|byte| ret.push(*byte));
            }
            Socks5Addr::Domain(domain, port) => {
                ret.push(Socks5AddrType::Domain as u8);
                // Throw a runtime error if the domain is longer than u8 bytes.
                ret.push(domain.len() as u8);
                domain.iter()
                    .for_each(|byte| ret.push(*byte));
                port
                    .to_be_bytes()
                    .iter()
                    .for_each(|byte| ret.push(*byte));
            }
            Socks5Addr::V6(socket_addr_v6) => {
                ret.push(Socks5AddrType::V6 as u8);
                socket_addr_v6.ip().octets().iter()
                    .for_each(|byte| ret.push(*byte));
                socket_addr_v6.port()
                    .to_be_bytes()
                    .iter()
                    .for_each(|byte| ret.push(*byte));
            }
        };
        ret
    }

    pub async fn read_and_parse_address(
        stream: &mut (impl AsyncReadTrait + std::marker::Unpin)
    ) -> Result<Socks5Addr> {
        info!("Reading address ...");
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;

        let addr_type = buf[0];
        let socks5_addr = match addr_type {
            0x01 => {
                debug_assert_eq!(addr_type, Socks5AddrType::V4 as u8);

                info!("Reading IPv4 address ...");
                let mut ipv4_buf = [0u8; 4];
                stream.read_exact(&mut ipv4_buf).await?;

                let port = Self::read_port(stream).await?;

                Socks5Addr::V4(
                    SocketAddrV4::new(
                        Ipv4Addr::new(ipv4_buf[0], ipv4_buf[1], ipv4_buf[2], ipv4_buf[3]),
                        port,
                    )
                )
            }
            0x03 => {
                debug_assert_eq!(addr_type, Socks5AddrType::Domain as u8);

                info!("Reading domain address len ...");
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;

                info!("Reading domain address ...");
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(domain_buf.as_mut_slice()).await?;

                let port = Self::read_port(stream).await?;

                Socks5Addr::Domain(domain_buf, port)
            }
            0x04 => {
                debug_assert_eq!(addr_type, Socks5AddrType::V6 as u8);

                info!("Reading IPv6 address ...");
                let mut ipv6_buf = [0u8; 16];
                stream.read_exact(&mut ipv6_buf).await?;

                let port = Self::read_port(stream).await?;

                Socks5Addr::V6(
                    SocketAddrV6::new(
                        Ipv6Addr::new(
                            u16::from_be_bytes(ipv6_buf[0..2].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[2..4].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[4..6].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[6..8].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[8..10].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[10..12].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[12..14].try_into().unwrap()),
                            u16::from_be_bytes(ipv6_buf[14..16].try_into().unwrap()),
                        ),
                        port,
                        0,
                        0,
                    )
                )
            }
            _ => {
                error!("Unsupported address type {}", addr_type);
                return Err(Error::UnsupportedAddressType(addr_type));
            }
        };
        info!("Socket address processed.");
        debug!("Address is {:?}", socks5_addr);
        return Ok(socks5_addr);
    }

    async fn read_port(
        stream: &mut (impl AsyncReadTrait + std::marker::Unpin)
    ) -> Result<u16> {
        info!("Reading port number ...");
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;

        let port = u16::from_be_bytes(port_buf);
        Ok(port)
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::ready_buf::ReadyBuf;

    use super::*;

    #[tokio::test]
    async fn test_parse_ipv4() -> Result<()> {
        let mut buf = ReadyBuf::make(&[&[0x01, 192, 168, 100, 1, 2, 1]]);
        let addr = Socks5Addr::read_and_parse_address(&mut buf).await?;

        assert_eq!(
            addr,
            Socks5Addr::V4(
                SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 100, 1),
                    513,
                )
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_ipv4_async() -> Result<()> {
        let mut buf = ReadyBuf::make(&[&[0x01, 192], &[168, 100, 1, 2], &[1]]);
        let addr = Socks5Addr::read_and_parse_address(&mut buf).await?;

        assert_eq!(
            addr,
            Socks5Addr::V4(
                SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 100, 1),
                    513,
                )
            )
        );
        assert_eq!(
            addr.bytes(),
            &[1, 192, 168, 100, 1, 2, 1],
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_domain_async() -> Result<()> {
        let mut buf = ReadyBuf::make(
            &[&[0x03], &[15], "www.ditsing.com".as_bytes(), &[0, 80]]
        );
        let addr = Socks5Addr::read_and_parse_address(&mut buf).await?;

        assert_eq!(
            addr,
            Socks5Addr::Domain("www.ditsing.com".as_bytes().to_vec(), 80)
        );
        assert_eq!(
            addr.bytes(),
            &[3, 15, 119, 119, 119, 46, 100, 105, 116, 115, 105, 110, 103, 46, 99, 111, 109, 0, 80],
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_ipv6_async() -> Result<()> {
        // It happens to be a correct v6 address as well.
        let mut buf = ReadyBuf::make(
            &[&[0x04], &[20], "www.ditsing.com".as_bytes(), &[0, 80]]
        );
        let addr = Socks5Addr::read_and_parse_address(&mut buf).await?;

        assert_eq!(
            addr,
            Socks5Addr::V6(
                SocketAddrV6::new(
                    Ipv6Addr::new(
                        0x1477, 0x7777, 0x2E64, 0x6974, 0x7369, 0x6E67, 0x2E63, 0x6F6D,
                    ),
                    80,
                    0,
                    0,
                )
            )
        );
        assert_eq!(
            addr.bytes(),
            &[4, 20, 119, 119, 119, 46, 100, 105, 116, 115, 105, 110, 103, 46, 99, 111, 109, 0, 80],
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_unsupported_address_type() -> Result<()> {
        let mut buf = ReadyBuf::make(
            &[&[0x02], &[20], "www.ditsing.com".as_bytes(), &[0, 80]]
        );
        let result = Socks5Addr::read_and_parse_address(&mut buf).await;
        if let Err(Error::UnsupportedAddressType(t)) = result {
            assert_eq!(t, 0x02);
        } else {
            panic!("Expecting error UnsupportedAddressType, got {:?}", result);
        }

        Ok(())
    }
}
