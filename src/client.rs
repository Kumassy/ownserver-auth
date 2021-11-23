use thiserror::Error;
use crate::{TokenResponse, TOKEN_SERVER_API_VERSION};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to connect to token server or failed to parse message from token server: {0}.")]
    ConnectionError(#[from] reqwest::Error),
    #[error("Client does not support token server version: {0}.")]
    VersionMismatch(u16),
    #[error("Token server error: {0}.")]
    TokenServerError(String),
}

pub async fn post_request_token(url: &str) -> Result<(String, String), Error> {
    let client = reqwest::Client::new();
    let resp = client.post(url)
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;


    match resp {
        TokenResponse::TokenResponseOk {version, token, host} if version == TOKEN_SERVER_API_VERSION => {
            Ok((token, host))
        },
        TokenResponse::TokenResponseOk {version, ..} => {
            Err(Error::VersionMismatch(version))
        },
        TokenResponse::TokenResponseErr { message, .. } => {
            Err(Error::TokenServerError(message))
        }
    }
}

#[cfg(test)]
mod tests_client {
    use super::*;
    use crate::{build_routes, decode_jwt};
    use warp::{
        Filter, http::StatusCode,
    };

    #[tokio::test]
    async fn client_parse_ok_response() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test";
        let hosts = vec![
            "foo.local".to_string(),
            "bar.local".to_string(),
            "baz.local".to_string()
        ];
        let routes = build_routes(secret, hosts.clone());
        tokio::spawn(async move {
            warp::serve(routes).run(([127, 0, 0, 1], 11111)).await;
        });

        let (token, host) = post_request_token("http://localhost:11111/request_token").await?;
        let claim = decode_jwt(secret, &token)?;
        assert!(hosts.contains(&claim.host));
        Ok(())
    }

    #[tokio::test]
    async fn client_returns_error_when_token_server_connection_error() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test";
        let hosts = vec![
            "foo.local".to_string(),
            "bar.local".to_string(),
            "baz.local".to_string()
        ];
        let routes = build_routes(secret, hosts.clone());
        tokio::spawn(async move {
            warp::serve(routes).run(([127, 0, 0, 1], 11112)).await;
        });

        let result = post_request_token("http://localhost:11112/this_is_invalid_path").await;
        assert!(result.is_err());

        let error = result.err().unwrap();
        assert!(matches!(error, Error::ConnectionError(_)));
        Ok(())
    }

    #[tokio::test]
    async fn client_returns_error_when_token_server_version_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let routes = warp::post().and(warp::path("request_token")).map(|| {
            let response = TokenResponse::TokenResponseOk {
                version: TOKEN_SERVER_API_VERSION + 100,
                token: "foobartoken".to_string(),
                host: "foohost.local".to_string()
            };
            warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
        });
        tokio::spawn(async move {
            warp::serve(routes).run(([127, 0, 0, 1], 11113)).await;
        });

        let result = post_request_token("http://localhost:11113/request_token").await;
        assert!(result.is_err());

        let error = result.err().unwrap();
        assert!(matches!(error, Error::VersionMismatch(_)));

        if let Error::VersionMismatch(version) = error {
            assert_eq!(version, TOKEN_SERVER_API_VERSION + 100);
        } else {
            panic!("unexpected error variant");
        }
        Ok(())
    }

    #[tokio::test]
    async fn client_returns_error_when_token_server_internal_error() -> Result<(), Box<dyn std::error::Error>> {
        let routes = warp::post().and(warp::path("request_token")).map(|| {
            let response = TokenResponse::TokenResponseErr {
                    version: 0,
                    message: "failed to generate token".into()
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::INTERNAL_SERVER_ERROR)
        });
        tokio::spawn(async move {
            warp::serve(routes).run(([127, 0, 0, 1], 11114)).await;
        });

        let result = post_request_token("http://localhost:11114/request_token").await;
        assert!(result.is_err());

        let error = result.err().unwrap();
        assert!(matches!(error, Error::TokenServerError(_)));

        if let Error::TokenServerError(message) = error {
            assert_eq!(message, "failed to generate token".to_string());
        } else {
            panic!("unexpected error variant");
        }
        Ok(())
    }
}