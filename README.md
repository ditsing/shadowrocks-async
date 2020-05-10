Shadowrocks
===========
***Throwing rocks against the wall***

Shadowrocks is a [`shadowsocks`](http://shadowsocks.org) port written in pure `async/.await` Rust.
At the moment it only does the basics: tunneling from a local SOCKS5 server to a remote server, with
proper encryption. The implementation is thoroughly tested and is compatible with the [original
python version][1] with `--compatible-mode`.

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

Compatibility
-------------
In non-compatible mode, a few changes are made to the traffic between the socks
server and shadow server.

1. Master key is derived using [`PBKDF2`][4], as opposite to [`PBKDF1`][5] used in
the original version. Master key is still derived from the password.
2. Sub-keys are derived using [`HKDF`][6] with `SHA256`, instead of `SHA1`, which is
no longer considered secure. The input key to `HKDF` is still the master key.
3. During encryption handshake, the salt used by the socks server to encrypt
outgoing traffic is designated by the shadow server, while the salt used by the
shadow server is designated by the socks server. The is the opposite to the
original version, where each server decides their own salt.

Item #3 helps defined against replay attacks. If we can reasonably assume that
salt generated is different each time, then both servers have to re-encrypt
traffic for every new connection. Attackers will need to derive a different
sub-key for the replied session, which cannot be done without the master key.

In compatible mode, `shadowrocks` behaves the same as the original version.

Features
---------------
- [x] TCP tunneling
- [ ] Integrate Clippy
- [ ] Benchmarks
- [ ] Integration testing
- [ ] Crate level documentation
- [ ] Document the code in `src/crypto` in detail
- [ ] UDP tunneling with optional fake-tcp
- [ ] Replay attack mitigation in compatible mode
- [x] Replay attack mitigation in non-compatible mode
- [ ] Native obfuscation
- [ ] Come up with more features to implement

[1]: https://github.com/shadowsocks/shadowsocks "shadowsocks"
[2]: https://github.com/shadowsocks/shadowsocks-rust "shadowsocks-rust"
[3]: https://github.com/shadowsocks/shadowsocks-org/issues/27 "SIP002"
[4]: https://tools.ietf.org/html/rfc2898#section-5.2
[5]: https://tools.ietf.org/html/rfc2898#section-5.1
[6]: https://tools.ietf.org/html/rfc5869
