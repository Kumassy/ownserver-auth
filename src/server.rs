use std::sync::{Arc, Mutex};
use chrono::Duration;
use warp::{
    Filter, http::StatusCode,
};
use crate::{make_jwt, Scheduler, TokenResponse};

pub fn build_routes(secret: &'static str, hosts: Vec<String>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let scheduler = Arc::new(Mutex::new(Scheduler::new(hosts)));

    let health_check = warp::get().and(warp::path("health_check")).map(|| {
        "ok"
    });

    let request_token = warp::post().and(warp::path("request_token")).map(move || {
        let scheduler = scheduler.clone();
        let mut scheduler = scheduler.lock().unwrap();

        match scheduler.allocate_host().map(|host| make_jwt(secret, Duration::minutes(10), host.to_string())) {
            Some(Ok(token)) => {
                let response = TokenResponse::TokenResponseOk {
                    version: 0,
                    token,
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
            },
            Some(Err(e)) => {
                // fail if and only if the combination of header and secret are invalid
                // this would not happen in production
                tracing::error!("failed to generate token {:?}", e);
                let response = TokenResponse::TokenResponseErr {
                    version: 0,
                    message: "failed to generate token".into()
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::INTERNAL_SERVER_ERROR)
            },
            None => {
                tracing::error!("failed to allocate host");
                let response = TokenResponse::TokenResponseErr {
                    version: 0,
                    message: "failed to allocate host".into()
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    });

    health_check.or(request_token).with(warp::trace::request())
}


#[cfg(test)]
mod tests_routes {
    use super::*;
    use std::str;
    use crate::decode_jwt;

    #[tokio::test]
    async fn test_health_check() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test";
        let hosts = vec![
            "foo.local".to_string(),
            "bar.local".to_string(),
            "baz.local".to_string()
        ];

        let req = warp::test::request().path("/health_check");
        let resp = req.reply(&build_routes(secret, hosts)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body = str::from_utf8(resp.body())?;
        assert_eq!(body, "ok".to_string());
        Ok(())
    }

    #[tokio::test]
    async fn test_request_token() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test";
        let hosts = vec![
            "foo.local".to_string(),
            "bar.local".to_string(),
            "baz.local".to_string()
        ];

        let req = warp::test::request().method("POST").path("/request_token");
        let resp = req.reply(&build_routes(secret, hosts.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let response: TokenResponse = serde_json::from_slice(resp.body())?;
        if let TokenResponse::TokenResponseOk {version, token} = response {
            assert_eq!(version, 0);
            let claim = decode_jwt("test", &token)?;
            assert_eq!(claim.version, 0);
            assert!(hosts.contains(&claim.host));
        } else {
            panic!("token response must be ok");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fail_to_create_request_token_when_hosts_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test";
        let hosts = vec![
        ];

        let req = warp::test::request().method("POST").path("/request_token");
        let resp = req.reply(&build_routes(secret, hosts.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        
        // let body = str::from_utf8(resp.body())?;
        // assert_eq!(body, "failed to allocate host".to_string());


        let response: TokenResponse = serde_json::from_slice(resp.body())?;
        if let TokenResponse::TokenResponseErr {version, message } = response {
            assert_eq!(version, 0);
            assert_eq!(message, "failed to allocate host".to_string());
        } else {
            panic!("token response must be err");
        }
        Ok(())
    }
}