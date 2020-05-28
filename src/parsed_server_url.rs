use std::str::FromStr;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::{Error, Result};

/// A struct to hold information contained in a `ss://` URL.
///
/// Query parameters are not yet supported. Plugin support will be added as they
/// are being implemented.
pub struct ParsedServerUrl {
    server_addr: (String, u16),
    encryption_method: String,
    password: Vec<u8>,
}

impl FromStr for ParsedServerUrl {
    type Err = Error;

    fn from_str(url_str: &str) -> Result<Self> {
        Self::from_url_string(url_str)
    }
}

impl ParsedServerUrl {
    pub fn server_addr(&self) -> (&str, u16) {
        (self.server_addr.0.as_str(), self.server_addr.1)
    }

    pub fn encryption_method(&self) -> &str {
        self.encryption_method.as_str()
    }

    pub fn password(&self) -> &[u8] {
        self.password.as_slice()
    }
}

impl ParsedServerUrl {
    /// Parse SS URL, the format of which is specified in
    /// https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
    pub fn from_url_string(url_str: &str) -> Result<ParsedServerUrl> {
        let parsed_url = match Url::parse(url_str) {
            Ok(parsed_url) => parsed_url,
            Err(e) => {
                return Err(Error::InvalidServerUrl(format!(
                    "Not a valid URL: {}",
                    e
                )))
            }
        };

        if parsed_url.scheme() != "ss" {
            return Err(Error::InvalidServerUrl("Scheme is not 'ss'".into()));
        }

        // userinfo = web-safe-base64.encode("{auth-method}:{password}")
        let userinfo =
            match percent_decode_str(parsed_url.username()).decode_utf8() {
                Ok(userinfo) => userinfo.to_string(),
                Err(e) => {
                    return Err(Error::InvalidServerUrl(format!(
                        "Cannot parse userinfo into UTF8: {}",
                        e
                    )))
                }
            };
        let auth_and_password =
            match base64::decode_config(userinfo, base64::URL_SAFE) {
                Ok(auth_and_password) => auth_and_password,
                Err(e) => {
                    return Err(Error::InvalidServerUrl(format!(
                        "Failed to decode base64 userinfo: {}",
                        e
                    )))
                }
            };

        // Split into (auth method, password) pair.
        let mut iter = auth_and_password.split(|c| *c == b':');
        let auth = iter.next().expect("Split returns at least one element");

        let auth_str = std::str::from_utf8(auth).map_err(|e| {
            Error::InvalidServerUrl(format!(
                "Cannot parse auth method into UTF8 string: {}",
                e
            ))
        })?;

        let password = iter.next().ok_or_else(|| {
            Error::InvalidServerUrl("Cannot find password in userinfo".into())
        })?;
        if iter.next().is_some() {
            return Err(Error::InvalidServerUrl(
                "There are more than two components in userinfo".into(),
            ));
        }

        let host = parsed_url.host_str().ok_or_else(|| {
            // This actually will never happen. An "empty host" error will be
            // thrown at the beginning if there is no host.
            Error::InvalidServerUrl("Cannot find server address".into())
        })?;
        let port = parsed_url.port().ok_or_else(|| {
            Error::InvalidServerUrl("Cannot find server port".into())
        })?;

        Ok(ParsedServerUrl {
            server_addr: (host.to_owned(), port),
            encryption_method: auth_str.into(),
            password: password.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid_server_url(result: Result<ParsedServerUrl>, msg: &str) {
        if let Err(Error::InvalidServerUrl(s)) = result {
            assert_eq!(s, msg);
        } else {
            panic!("Expecting invalid server URL error.");
        }
    }

    #[test]
    fn test_server_url_parse() -> Result<()> {
        let server_url = ParsedServerUrl::from_url_string(
            "ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:8888/\
            ?plugin=obfs-local%3Bobfs%3Dhttp#Example2",
        )?;
        assert_eq!(server_url.server_addr, ("192.168.100.1".to_owned(), 8888));
        assert_eq!(server_url.encryption_method, "rc4-md5");
        assert_eq!(server_url.password, b"passwd");

        Ok(())
    }

    #[test]
    fn test_server_url_parse_two() -> Result<()> {
        let server_url = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0@127.0.0.1:51986",
        )?;
        assert_eq!(server_url.server_addr, ("127.0.0.1".to_owned(), 51986));
        assert_eq!(server_url.encryption_method, "xchacha20-ietf-poly1305");
        assert_eq!(server_url.password, b"test-test");

        Ok(())
    }

    #[test]
    fn test_server_url_not_url() -> Result<()> {
        let result = ParsedServerUrl::from_url_string("/");
        assert_invalid_server_url(
            result,
            "Not a valid URL: relative URL without a base",
        );

        Ok(())
    }

    #[test]
    fn test_server_url_scheme_mismatch() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "sss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0@127.0.0.1:51986",
        );
        assert_invalid_server_url(result, "Scheme is not \'ss\'");

        Ok(())
    }

    #[test]
    fn test_server_url_not_utf8() -> Result<()> {
        let result =
            ParsedServerUrl::from_url_string("ss://%a0%a1@127.0.0.1:51986");
        assert_invalid_server_url(
            result,
            "Cannot parse userinfo into UTF8: \
            invalid utf-8 sequence of 1 bytes from index 0",
        );

        Ok(())
    }

    #[test]
    fn test_server_url_not_base64() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0=@127.0.0.1:51986",
        );
        assert_invalid_server_url(
            result,
            "Failed to decode base64 userinfo: \
            Encoded text cannot have a 6-bit remainder.",
        );

        Ok(())
    }

    #[test]
    fn test_server_url_auth_not_utf8() -> Result<()> {
        // echo -n "\xa0\xa1xchacha20-ietf-poly1305:test-test" | base64
        let result = ParsedServerUrl::from_url_string(
            "ss://oKF4Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXRlc3Q=@127.0.0.1:51986"
        );
        assert_invalid_server_url(
            result,
            "Cannot parse auth method into UTF8 string: \
            invalid utf-8 sequence of 1 bytes from index 0",
        );

        Ok(())
    }

    #[test]
    fn test_server_url_no_password() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU=@127.0.0.1:51986",
        );
        assert_invalid_server_url(result, "Cannot find password in userinfo");

        Ok(())
    }

    #[test]
    fn test_server_url_too_many_passwords() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0Og==@127.0.0.1:51986",
        );
        assert_invalid_server_url(
            result,
            "There are more than two components in userinfo",
        );

        Ok(())
    }

    #[test]
    fn test_server_url_no_host() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0@",
        );
        assert_invalid_server_url(result, "Not a valid URL: empty host");

        Ok(())
    }

    #[test]
    fn test_server_url_no_port() -> Result<()> {
        let result = ParsedServerUrl::from_url_string(
            "ss://eGNoYWNoYTIwLWlldGYtcG9seTEzMDU6dGVzdC10ZXN0@127.0.0.1",
        );
        assert_invalid_server_url(result, "Cannot find server port");

        Ok(())
    }
}
