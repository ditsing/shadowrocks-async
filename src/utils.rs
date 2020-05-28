const UNKNOWN_ADDR: (&str, u16) = ("127.0.0.1", 0);

/// A convenient function that creates a TCP listener locally, on a random port.
pub fn create_any_tcp_listener() -> std::io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind(UNKNOWN_ADDR)
}
