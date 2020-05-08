use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use async_trait::async_trait;

use crate::socks5_addr::Socks5Addr;
use crate::Result;

#[async_trait]
pub trait AsyncReadTrait {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[async_trait]
pub trait AsyncWriteTrait {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<usize>;
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()>;
}

#[async_trait]
impl<T: AsyncReadExt + std::marker::Send + std::marker::Unpin + ?Sized> AsyncReadTrait for T {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        <T as AsyncReadExt>::read(self, buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        <T as AsyncReadExt>::read_exact(self, buf).await
    }
}

#[async_trait]
impl<T: AsyncWriteExt + std::marker::Send + std::marker::Unpin + ?Sized> AsyncWriteTrait for T {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        <T as AsyncWriteExt>::write(self, data).await
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        <T as AsyncWriteExt>::write_all(self, data).await
    }
}

pub trait SplitIntoAsync {
    type R: AsyncReadTrait + std::marker::Send + std::marker::Unpin + std::marker::Sized;
    type W: AsyncWriteTrait + std::marker::Send + std::marker::Unpin + std::marker::Sized;

    fn into_split(self) -> (Self::R, Self::W);
}

impl SplitIntoAsync for TcpStream {
    type R = OwnedReadHalf;
    type W = OwnedWriteHalf;

    fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        TcpStream::into_split(self)
    }
}

pub async fn copy(mut reader: impl AsyncReadTrait, mut writer: impl AsyncWriteTrait) -> Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        info!("Copy reading bytes ...");
        let bytes = reader.read(&mut buf).await?;
        if bytes == 0 {
            info!("Copy got EOF");
            return Ok(());
        }
        info!("Copy read {} bytes", bytes);
        writer.write_all(&buf[..bytes]).await?;
        info!("Copy wrote {} bytes", bytes);
    }
}

pub fn proxy(
    local: impl SplitIntoAsync + std::marker::Send + 'static,
    remote: impl SplitIntoAsync + std::marker::Send + 'static,
    name: Socks5Addr,
) {
    tokio::spawn(async move {
        let (local_reader, local_writer) = local.into_split();
        let (remote_reader, remote_writer) = remote.into_split();
        let upstream = copy(local_reader, remote_writer);
        let downstream = copy(remote_reader, local_writer);
        let (upstream_result, downstream_result) = tokio::join!(upstream, downstream);
        if let Err(e) = upstream_result {
            warn!("Error proxying data, upstream failed: {}", e);
        }
        if let Err(e) = downstream_result {
            warn!("Error proxying data, downstream failed: {}", e);
        }
        info!("Shutting down proxy to {:?}", name);
    });
}
