Shadowrocks
===========
***Throwing rocks against the wall***

Shadowrocks is a [`shadowsocks`](http://shadowsocks.org) port written in pure `async/.await` Rust.
At the moment it only does the basics: tunneling from a local SOCKS5 server to a remote server, with
proper encryption. The implementation is thoroughly tested and is compatible with the [original
python version][1].

The official Rust implementation of `shadowsocks` can be found [here][2]. It has way more
functionality.

How to run
----------
JSON configuration files and `ss://` URLs described in [SIP002][3] are not yet supported.

To start the local SOCKS5 server at port `51980`, run
```shell script
cargo run -- -l 51980 -s 127.0.0.1 -p 51986 -k test-password
```

In the meantime, start the remote shadow server by running
```shell script
cargo run -- --shadow -s 127.0.0.1 -p 51986 -k test-password
```
The server address (`-s`), server port (`-p`) and password (`-k`) flags must match.

Encryption
----------
Four types of ciphers are supported:

* `chacha20-ietf-poly1305` provided by sodium
* `aes-128-gcm` by OpenSSL
* `aes-192-gcm` by OpenSSL
* `aes-256-gcm` by OpenSSL

All of them are AEAD ciphers.

Features
---------------
- [x] TCP tunneling
- [ ] Integrate Clippy
- [ ] Benchmarks
- [ ] Integration testing
- [ ] Crate level documentation
- [ ] Document the code in `src/crypto` in detail
- [ ] UDP tunneling with optional fake-tcp
- [ ] Replay attack mitigation
- [ ] Native obfuscation
- [ ] Come up with more features to implement

[1]: https://github.com/shadowsocks/shadowsocks "shadowsocks"
[1]: https://github.com/shadowsocks/shadowsocks-rust "shadowsocks-rust"
[2]: https://github.com/shadowsocks/shadowsocks-org/issues/27 "SIP002"

