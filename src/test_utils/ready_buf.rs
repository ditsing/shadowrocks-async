use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::io::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// A buffer that supports both AsyncRead and AsyncWrite.
// Could possibly be replaced by bytes::BufMut or tokio_test::io::Mock.
pub struct ReadyBuf {
    buf_list: VecDeque<VecDeque<u8>>,
}

impl AsyncRead for ReadyBuf {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let real_self = std::pin::Pin::into_inner(self);
        match real_self.buf_list.pop_front() {
            Some(mut data) => {
                let (first, second) = data.as_slices();
                assert!(second.is_empty());
                let len = std::cmp::min(buf.remaining(), first.len());
                buf.put_slice(&first[0..len]);
                data.drain(..len);
                if !data.is_empty() {
                    real_self.buf_list.push_front(data);
                }
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for ReadyBuf {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let real_self = std::pin::Pin::into_inner(self);
        real_self.buf_list.push_back(VecDeque::from(buf.to_vec()));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl ReadyBuf {
    pub fn make(byte_arrays: &[&[u8]]) -> Self {
        let mut buf_list: VecDeque<VecDeque<u8>> = VecDeque::new();
        for &byte_array in byte_arrays {
            // TODO: WTF, &[u8] to vec to deque?
            buf_list.push_back(VecDeque::from(byte_array.to_vec()));
        }
        ReadyBuf { buf_list }
    }

    pub fn combined(self) -> Vec<u8> {
        let mut buf = vec![];
        for deque in self.buf_list {
            buf.append(&mut Vec::from(deque));
        }
        buf
    }
}

impl Unpin for ReadyBuf {}
