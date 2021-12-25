use chrono::Duration;
use magic_tunnel_auth::{make_jwt, decode_jwt, build_routes};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let secret = "supersecret";
    let token = make_jwt(
        secret,
        Duration::minutes(10),
        "hoge-id".to_string(),
    );
    println!("token: {:?}", token);
    println!("decoded: {:?}", decode_jwt(secret, &token?));

    let hosts = vec![
        // "foo.local".to_string(),
        // "bar.local".to_string(),
        // "baz.local".to_string()
        "foohost.local".to_string(),
    ];

    let routes = build_routes(secret, hosts);
    warp::serve(routes).run(([0, 0, 0, 0], 8123)).await;
    Ok(())
}
