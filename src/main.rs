use chrono::prelude::*;
use chrono::Duration;
use warp::{
    ws::{Message, WebSocket, Ws},
    Error as WarpError, Filter,
    http::StatusCode,
};
use std::sync::{Arc, Mutex};
use magic_tunnel_auth::{make_jwt, decode_jwt, Scheduler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let secret = "supersecretsharedpassphrased";
    let token = make_jwt(
        secret,
        Duration::minutes(10),
        "hoge-id".to_string(),
    );
    println!("token: {:?}", token);
    println!("decoded: {:?}", decode_jwt(secret, &token?));

    let hosts = vec![
        "foo.local".to_string(),
        "bar.local".to_string(),
        "baz.local".to_string()
    ];
    let scheduler = Arc::new(Mutex::new(Scheduler::new(hosts)));

    let health_check = warp::get().and(warp::path("health_check")).map(|| {
        "ok"
    });

    let request_token = warp::post().and(warp::path("request_token")).map(move || {
        let scheduler = scheduler.clone();
        let mut scheduler = scheduler.lock().unwrap();

        match scheduler.allocate_host() {
            Some(host) => {
                match make_jwt(secret, Duration::minutes(10), host.to_string()) {
                    Ok(token) => {
                        warp::reply::with_status(token, StatusCode::OK)
                    },
                    Err(e) => {
                        tracing::error!("failed to generate token");
                        warp::reply::with_status("failed to generate token".into(), StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            },
            None => {
                tracing::warn!("failed to allocate host");
                warp::reply::with_status("failed to allocate host".into(), StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    });

    let routes = health_check.or(request_token).with(warp::trace::request());

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}
