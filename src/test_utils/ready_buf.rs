use std::collections::VecDeque;
use std::task::Context;

use tokio::io::AsyncRead;
use tokio::macros::support::{Pin, Poll};

pub struct ReadyBuf {
    buf_list: VecDeque<VecDeque<u8>>,
}

impl AsyncRead for ReadyBuf {
    fn poll_read(
        self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let real_self = std::pin::Pin::into_inner(self);
        match real_self.buf_list.pop_front() {
            Some(mut data) => {
                let mut len = 0;
                while len < buf.len() && !data.is_empty() {
                    buf[len] = data.pop_front().expect("deque should be non-empty.");
                    len += 1;
                }
                if !data.is_empty() {
                    real_self.buf_list.push_front(data);
                }
                Poll::Ready(Ok(len))
            }
            None => Poll::Ready(Ok(0)),
        }
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
}

impl std::marker::Unpin for ReadyBuf {}
