pub mod local_tcp_server;
pub mod plaintext_crypter;
pub mod ready_buf;

macro_rules! crypto_array {
    ($ ($ x : expr), *) => {
        [$($x),*]
    };
    ($ ($ x : expr,) *) => {
        [$($x,)*]
    };
}

macro_rules! crypto_vec {
    ($ ($ x : expr), *) => {
        vec![$($x),*]
    };
    ($ ($ x : expr,) *) => {
        vec![$($x,)*]
    };
}
