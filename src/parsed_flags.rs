use std::fs::File;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Debug)]
struct SocketAddrFlag(String, u16);

/// A struct that holds parsed commandline flags, for both the local and remote
/// servers.
pub struct ParsedFlags {
    server_addr: Option<SocketAddrFlag>,
    local_addr: Option<SocketAddrFlag>,

    password: Vec<u8>,
    encryption_method: Option<String>,

    timeout: Option<Duration>,
    fast_open: Option<bool>,
}

// Wrap server_addr and local_addr so that they can be converted to SocketAddr.
impl ParsedFlags {
    pub fn server_addr(&self) -> Option<(&str, u16)> {
        self.server_addr
            .as_ref()
            .map(|addr| (addr.0.as_str(), addr.1))
    }

    pub fn local_addr(&self) -> Option<(&str, u16)> {
        self.local_addr
            .as_ref()
            .map(|addr| (addr.0.as_str(), addr.1))
    }

    pub fn password(&self) -> &[u8] {
        self.password.as_ref()
    }

    pub fn encryption_method(&self) -> Option<&str> {
        self.encryption_method.as_deref()
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn fast_open(&self) -> Option<bool> {
        self.fast_open
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    server: Option<String>,
    server_port: Option<u16>,

    local_address: Option<String>,
    local_port: Option<u16>,

    password: String,

    method: Option<String>,

    // Timeout in seconds.
    timeout: Option<u64>,

    fast_open: Option<bool>,
}

impl ParsedFlags {
    fn parse_addr(
        addr: Option<String>,
        port: Option<u16>,
        name: &str,
    ) -> Result<Option<SocketAddrFlag>> {
        match (addr, port) {
            (Some(local), Some(port)) => Ok(Some(SocketAddrFlag(local, port))),
            (None, None) => Ok(None),
            _ => Err(Error::InvalidConfigFile(format!(
                "{} must be specified together.",
                name
            ))),
        }
    }

    pub fn from_config_file<P: AsRef<Path>>(
        file_name: P,
    ) -> Result<ParsedFlags> {
        let file = File::open(file_name)?;
        let config_file: ConfigFile = serde_json::from_reader(file)
            .map_err(|e| Error::InvalidConfigFile(e.to_string()))?;

        let server_addr = Self::parse_addr(
            config_file.server,
            config_file.server_port,
            "'server' and 'server_port'",
        )?;

        let local_addr = Self::parse_addr(
            config_file.local_address,
            config_file.local_port,
            "'local_address' and 'local_port'",
        )?;

        Ok(ParsedFlags {
            server_addr,
            local_addr,

            password: config_file.password.into_bytes(),
            encryption_method: config_file.method,

            timeout: config_file.timeout.map(Duration::from_secs),
            fast_open: config_file.fast_open,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use rand::Rng;

    use crate::Result;

    use super::*;

    struct Tempfile(PathBuf);

    impl Tempfile {
        pub fn create(content: &str) -> std::io::Result<Self> {
            let rng = rand::thread_rng();
            let file_name: String = rng
                .sample_iter(rand::distributions::Alphanumeric)
                .take(10)
                .chain(".json".chars())
                .collect();

            let mut dir = std::env::temp_dir();
            dir.push(file_name);
            let mut file = std::fs::File::create(dir.clone())?;
            let ret = Self(dir);

            file.write_all(content.as_bytes())?;
            file.flush()?;

            Ok(ret)
        }
    }

    impl Drop for Tempfile {
        fn drop(&mut self) {
            std::fs::remove_file(self).expect("Unlink should not fail.")
        }
    }

    impl AsRef<Path> for Tempfile {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    #[test]
    fn test_parse_config_file() -> Result<()> {
        let config_file = Tempfile::create(
            r#"
        {
            "server": "8.8.4.4",
            "server_port": 99,
            "local_address": "127.0.0.1",
            "local_port": 88,
            "password": "1234567",
            "method": "plaintext",

            "timeout": 0,
            "fast_open": true
        }
        "#,
        )?;

        let parsed_flags = ParsedFlags::from_config_file(config_file)?;
        assert_eq!(parsed_flags.server_addr(), Some(("8.8.4.4", 99)));
        assert_eq!(parsed_flags.local_addr(), Some(("127.0.0.1", 88)));
        assert_eq!(parsed_flags.password, b"1234567");
        assert_eq!(
            parsed_flags.encryption_method,
            Some("plaintext".to_string())
        );
        assert_eq!(parsed_flags.timeout, Some(Duration::from_secs(0)));
        assert_eq!(parsed_flags.fast_open, Some(true));
        Ok(())
    }

    #[test]
    fn test_parse_config_file_optional_fields() -> Result<()> {
        let config_file = Tempfile::create(
            r#"
        {
            "password": "1234567"
        }
        "#,
        )?;

        let parsed_flags = ParsedFlags::from_config_file(config_file)?;
        assert_eq!(parsed_flags.server_addr(), None);
        assert_eq!(parsed_flags.local_addr(), None);
        assert_eq!(parsed_flags.password, b"1234567");
        assert_eq!(parsed_flags.encryption_method, None);
        assert_eq!(parsed_flags.timeout, None);
        assert_eq!(parsed_flags.fast_open, None);
        Ok(())
    }

    #[test]
    fn test_parse_config_file_no_password() -> Result<()> {
        let config_file = Tempfile::create(
            r#"
        {
            "local_address": "127.0.0.1",
            "local_port": 88
        }
        "#,
        )?;
        match ParsedFlags::from_config_file(config_file) {
            Ok(_) => {
                panic!("Parse should not work since password is required.")
            }
            Err(Error::InvalidConfigFile(s)) => {
                assert!(s.starts_with("missing field"))
            }
            _ => panic!("Expecting error to be InvalidConfigFile."),
        };
        Ok(())
    }

    #[test]
    fn test_parse_config_file_no_server_port() -> Result<()> {
        let config_file = Tempfile::create(
            r#"
        {
            "server": "127.0.0.1",
            "password": "1234567"
        }
        "#,
        )?;
        match ParsedFlags::from_config_file(config_file) {
            Ok(_) => panic!("Parse should not work since port is required."),
            Err(Error::InvalidConfigFile(s)) => {
                assert_eq!(
                    s,
                    "'server' and 'server_port' must be specified together."
                );
            }
            _ => panic!("Expecting error to be InvalidConfigFile."),
        };
        Ok(())
    }

    #[test]
    fn test_parse_config_file_no_local_address() -> Result<()> {
        let config_file = Tempfile::create(
            r#"
        {
            "local_port": 88,
            "password": "1234567"
        }
        "#,
        )?;
        match ParsedFlags::from_config_file(config_file) {
            Ok(_) => panic!("Parse should not work since address is required."),
            Err(Error::InvalidConfigFile(s)) => {
                assert_eq!(
                    s,
                    "'local_address' and 'local_port' must be specified together."
                );
            }
            _ => panic!("Expecting error to be InvalidConfigFile."),
        };
        Ok(())
    }
}
