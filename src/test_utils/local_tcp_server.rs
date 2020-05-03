use std::io::{Write, Read};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::info;

use crate::Result;

pub fn run_local_tcp_server() -> Result<(SocketAddr, Arc<AtomicBool>)> {
    let tcp_listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = tcp_listener.local_addr()?;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    std::thread::spawn(move || {
        let mut count = 0u32;
        for stream in tcp_listener.incoming() {
            count += 1;
            match stream {
                Ok(mut stream) => {
                    info!("Accepted connection {} from {}", count, stream.peer_addr()?);
                    let mut buf = [0u8; 2];
                    stream.read_exact(&mut buf)?;

                    if u16::from_be_bytes(buf) == 1990 {
                        stream.write_all(&1209u16.to_be_bytes())?;
                    }

                    stream.write_all(&count.to_be_bytes())?;
                }
                Err(e) => return Err(e),
            }
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
        Ok(())
    });

    Ok((local_addr, running_clone))
}
