use chrono::prelude::*;
use chrono::Duration;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    version: u16,
    host: String,
    iat: i64,
    exp: i64,
}

pub fn make_jwt(secret: &str, duration: Duration, host: String) -> Result<String, Error> {
    let header = Header {
        typ: Some("JWT".to_string()),
        alg: Algorithm::HS256,
        ..Default::default()
    };
    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + duration).timestamp();
    let my_claims = Claims {
        version: 0,
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

pub fn decode_jwt(secret: &str, token: &str) -> Result<Claims, Error> {
    let token_message = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    token_message.map(|data| data.claims)
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

        assert_eq!(decoded.version, 0);
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
}