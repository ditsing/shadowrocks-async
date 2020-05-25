#[derive(Debug)]
pub enum Error {
    UnsupportedSocksVersion(u8),
    UnexpectedReservedBit(u8),
    IOError(std::io::Error),
    MalformedDomainString(Vec<u8>, std::str::Utf8Error),
    UnknownHost(String),
    RelayAlreadyRunning,
    UnsupportedAddressType(u8),
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    UnknownCipher(String),
    InvalidConfigFile(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsupportedSocksVersion(v) => {
                write!(f, "Unsupported SOCKS version {}", v)
            }
            Error::UnexpectedReservedBit(rsv) => {
                write!(f, "Unexpected reserved bit {:#02X}", rsv)
            }
            Error::IOError(e) => write!(f, "IO error: {}", e),
            Error::MalformedDomainString(v, e) => {
                write!(f, "Malformed domain string {:?}: {}", v, e)
            }
            Error::UnknownHost(host) => {
                write!(f, "Cannot resolve host {}", host)
            }
            Error::RelayAlreadyRunning => write!(
                f,
                "Operation not allowed after the relay started running"
            ),
            Error::UnsupportedAddressType(addr_type) => {
                write!(f, "Unsupported address type {}", addr_type)
            }
            Error::KeyDerivationError => write!(f, "Key derivation error"),
            Error::EncryptionError => write!(f, "Encryption error"),
            Error::DecryptionError => write!(f, "Decryption error"),
            Error::UnknownCipher(s) => write!(f, "Unknown cipher {}", s),
            Error::InvalidConfigFile(s) => {
                write!(f, "Invalid config file {}", s)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IOError(error)
    }
}
