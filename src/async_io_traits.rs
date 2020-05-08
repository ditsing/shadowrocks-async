use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[async_trait]
pub trait AsyncReadTrait {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[async_trait]
pub trait AsyncWriteTrait {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()>;
}

#[async_trait]
impl<T: AsyncReadExt + std::marker::Send + std::marker::Unpin + ?Sized> AsyncReadTrait for T {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        <T as AsyncReadExt>::read_exact(self, buf).await
    }
}

#[async_trait]
impl<T: AsyncWriteExt + std::marker::Send + std::marker::Unpin + ?Sized> AsyncWriteTrait for T {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        <T as AsyncWriteExt>::write_all(self, data).await
    }
}
