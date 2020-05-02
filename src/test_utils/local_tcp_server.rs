use std::io::Write;
use std::net::{SocketAddr, TcpListener};

use log::info;

use crate::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn run_local_tcp_server() -> Result<(SocketAddr, Arc<AtomicBool>)> {
    let tcp_listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = tcp_listener.local_addr()?;
    let running = Arc::new(AtomicBool::new(false));
    let running_clone = running.clone();
    std::thread::spawn(move || {
        let mut count = 0u32;
        for stream in tcp_listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    info!("Accepted connection {} from {}", count, stream.peer_addr()?);
                    stream.write_all(&count.to_be_bytes())?;
                },
                Err(e) => return Err(e),
            }
            count += 1;
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
        Ok(())
    });

    Ok((local_addr, running_clone))
}
