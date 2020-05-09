pub mod local_tcp_server;
pub mod plaintext_crypter;
pub mod ready_buf;

// Does nothing and passes on everything to []. It is to prevent rustfmt
// to mess with plaintext or ciphertext.
macro_rules! crypto_array {
    ($ ($ x : expr), *) => {
        [$($x),*]
    };
    ($ ($ x : expr,) *) => {
        [$($x,)*]
    };
}

// Does nothing and passes on everything to vec![]. It is to prevent rustfmt
// to mess with plaintext or ciphertext.
macro_rules! crypto_vec {
    ($ ($ x : expr), *) => {
        vec![$($x),*]
    };
    ($ ($ x : expr,) *) => {
        vec![$($x,)*]
    };
}
