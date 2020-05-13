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

// `T: AsyncWriteExt + Unpin` guarantees that T has write() and write_all().
// `T: Send` guarantees that `self` can be used before and after an `.await`.
#[async_trait]
impl<T: AsyncReadExt + Send + Unpin + ?Sized> AsyncReadTrait for T {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        <T as AsyncReadExt>::read(self, buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        <T as AsyncReadExt>::read_exact(self, buf).await
    }
}

// `T: AsyncWriteExt + Unpin` guarantees that T has write() and write_all().
// `T: Send` guarantees that `self` can be the parameter of an async function.
#[async_trait]
impl<T: AsyncWriteExt + Send + Unpin + ?Sized> AsyncWriteTrait for T {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        <T as AsyncWriteExt>::write(self, data).await
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        <T as AsyncWriteExt>::write_all(self, data).await
    }
}

pub trait SplitIntoAsync {
    // Those two types must be sized, as we would like to allocate them on stack.
    // They also must implement `Send` because the results will be used in
    // async functions.
    type R: AsyncReadTrait + Send;
    type W: AsyncWriteTrait + Send;

    fn into_split(self) -> (Self::R, Self::W);
}

impl SplitIntoAsync for TcpStream {
    type R = OwnedReadHalf;
    type W = OwnedWriteHalf;

    fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        TcpStream::into_split(self)
    }
}

// Keep copying data from reader to writer, read and write up to 8KB data each time.
pub async fn copy(
    mut reader: impl AsyncReadTrait,
    mut writer: impl AsyncWriteTrait,
) -> Result<()> {
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

// Start a new task that proxies data between local and remote streams.
// This is not an `async` function. It should not block, either, assuming tokio::spawn() is fast.
pub fn proxy(
    // `local` and `remote` must implement `Send` because they'll be moved into
    // an async function, which might execute on a different thread.
    // They should not contain non-`'static` references, since the async
    // function can run arbitrarily long.
    local: impl SplitIntoAsync + Send + 'static,
    remote: impl SplitIntoAsync + Send + 'static,
    name: Socks5Addr,
) {
    tokio::spawn(async move {
        let (local_reader, local_writer) = local.into_split();
        let (remote_reader, remote_writer) = remote.into_split();
        let upstream = copy(local_reader, remote_writer);
        let downstream = copy(remote_reader, local_writer);
        let (upstream_result, downstream_result) =
            tokio::join!(upstream, downstream);
        if let Err(e) = upstream_result {
            warn!("Error proxying data, upstream failed: {}", e);
        }
        if let Err(e) = downstream_result {
            warn!("Error proxying data, downstream failed: {}", e);
        }
        info!("Shutting down proxy to {:?}", name);
    });
}
