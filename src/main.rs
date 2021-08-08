use chrono::prelude::*;
use chrono::Duration;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    account_id: String,
    iat: i64,
    exp: i64,
}

pub fn make_jwt(secret: &str, account_id: &str) -> String {
    let header = Header {
        typ: Some("JWT".to_string()),
        alg: Algorithm::HS256,
        ..Default::default()
    };
    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + Duration::hours(8)).timestamp();
    let my_claims = Claims {
        account_id: account_id.to_string(),
        iat,
        exp,
    };

    encode(
        &header,
        &my_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}

pub fn decode_jwt(secret: &str, token: &str) -> Result<Claims, Error> {
    let validation = Validation {
        algorithms: vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
        ..Default::default()
    };

    let token_message = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        // &Validation::new(Algorithm::HS256),
        &validation,
    );
    token_message.map(|data| data.claims)
}

fn main() {
    let secret = "supersecretsharedpassphrased";
    let token = make_jwt(
        secret,
        "hoge-id",
    );
    println!("token: {}", token);
    println!("decoded: {:?}", decode_jwt(secret, &token));
}
