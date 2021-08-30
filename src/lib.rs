use chrono::prelude::*;
use chrono::Duration;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::Error as JWTError};
use serde::{Deserialize, Serialize};
use rand::prelude::*;
use rand::rngs::StdRng;

mod client;
mod server;
pub use server::build_routes;
pub use client::{post_request_token, Error};

pub(crate) const TOKEN_SERVER_API_VERSION: u16 = 0;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub host: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn make_jwt(secret: &str, duration: Duration, host: String) -> Result<String, JWTError> {
    let header = Header {
        typ: Some("JWT".to_string()),
        alg: Algorithm::HS256,
        ..Default::default()
    };
    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + duration).timestamp();
    let my_claims = Claims {
        host,
        iat,
        exp,
    };

    encode(
        &header,
        &my_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

pub fn decode_jwt(secret: &str, token: &str) -> Result<Claims, JWTError> {
    let token_message = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    token_message.map(|data| data.claims)
}

pub struct Scheduler {
    hosts: Vec<String>,
    rng: StdRng
}

impl Scheduler {
    pub fn new(hosts: Vec<String>) -> Self {
        Scheduler {
            hosts,
            rng: StdRng::from_entropy(),
        }
    }

    pub fn allocate_host(&mut self) -> Option<&String> {
        self.hosts.iter().choose(&mut self.rng)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum TokenResponse {
    TokenResponseOk {
        version: u16,
        token: String,
    },
    TokenResponseErr {
        version: u16,
        message: String,
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn test_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "foobarbaz";
        let token = make_jwt(secret, Duration::minutes(10), "foo-host".to_string())?;
        let decoded = decode_jwt(secret, &token)?;

        assert_eq!(decoded.host, "foo-host".to_string());
        Ok(())
    }

    #[test]
    fn test_decode_with_invalid_secret() -> Result<(), Box<dyn std::error::Error>> {
        let token = make_jwt("foobarbaz", Duration::minutes(10), "foo-host".to_string())?;
        let decoded = decode_jwt("hogepiyo", &token);

        assert!(decoded.is_err());
        Ok(())
    }

    #[test]
    fn test_decode_after_expired() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "foobarbaz";
        let token = make_jwt(secret, Duration::seconds(3), "foo-host".to_string())?;

        sleep(std::time::Duration::from_secs(5));
        let decoded = decode_jwt(secret, &token);

        assert!(decoded.is_err());
        Ok(())
    }

    #[test]
    fn test_scheduler_ok() {
        let hosts = vec![
            "foo.local".to_string(),
            "bar.local".to_string(),
            "baz.local".to_string()
        ];
        let mut scheduler = Scheduler::new(hosts.clone());

        assert!(hosts.contains(scheduler.allocate_host().unwrap()));
    }

    #[test]
    fn test_scheduler_fail() {
        let hosts = vec![
        ];
        let mut scheduler = Scheduler::new(hosts);

        assert!(scheduler.allocate_host().is_none());
    }
}