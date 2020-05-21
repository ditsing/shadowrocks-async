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
* `xchacha20-ietf-poly1305` provided by sodium
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

Crypto dependencies
-------------------
Both the [`ring` crate][7] (BoringSSL) and the [`openssl` crate][8] are used.
The functionality largely overlaps between those two. `ring` was originally
used as a reference point and sanity check to `openssl`, when the author is
unfamiliar with the crypto used in `shadowsocks`.

### `ring` and `openssl` feature table
| features    | `ring` | `openssl` |
|:------------|:------:|:---------:|
|  `PBKDF1`   |        |     ✅   |
|  `PBKDF2`   |   ✅   |     ✅   |
|`HKDF-SHA1`  |   ✅   |     ✅   |
|`HKDF-SHA256`|   ✅   |     ✅   |
|`AES-128-GCM`|   ✅   |     ✅   |
|`AES-192-GCM`|        |     ✅   |
|`AES-256-GCM`|   ✅   |     ✅   |

`HKDF-SHA1` support was [recently][9] added to `ring`.

The `ring` crate can be disabled by disabling feature `ring-crypto`. The
`openssl` crate cannot be completely disabled at the moment.

Improvements
------------
- [ ] Reduce memory allocation in the encryption / decryption process.

The current implementation does a lot of small memory allocations for each
connection. For example, to send the SOCKS 5 address from socks server to
remote shadow server, the following process is followed.

1. Turning SOCKS 5 address into bytes.
2. Turning packet length into bytes (`x` bytes, `x = 2`).
3. Turning nonce into bytes (4 bytes).
4. An OpenSSL crypter object.
5. Ciphertext of packet length (`x` bytes, `x = 2`).
6. Tag for the encryption (16 bytes).
7. Concatenation of ciphertext and tag (18 bytes).
8. Repeat 2-7 for SOCKS5 address with `x` varies.

To summarize, 13 allocations for each packet. Each encryption costs 6
allocations, and each packet we have to encrypt twice: once for packet length
and once for the actual information.

The process for reading is similar.
1. Ciphertext of packet length.
2. Tag for encryption
3. Turning nonce into bytes
4. An OpenSSL crypter object.
5. Packet length plaintext.
6. Repeat 1-5 for packet content.

We saved one step for the "ciphertext without tag" part. Nonetheless this is
still terrible.

[1]: https://github.com/shadowsocks/shadowsocks "shadowsocks"
[2]: https://github.com/shadowsocks/shadowsocks-rust "shadowsocks-rust"
[3]: https://github.com/shadowsocks/shadowsocks-org/issues/27 "SIP002"
[4]: https://tools.ietf.org/html/rfc2898#section-5.2 "RFC 2898"
[5]: https://tools.ietf.org/html/rfc2898#section-5.1 "RFC 2898"
[6]: https://tools.ietf.org/html/rfc5869 "RFC 5869"
[7]: https://briansmith.org/rustdoc/ring/index.html "ring"
[8]: https://github.com/sfackler/rust-openssl "openssl"
[9]: https://github.com/briansmith/ring/commit/f81232fe69f21ba0c490507e579e15be2333f0d7
