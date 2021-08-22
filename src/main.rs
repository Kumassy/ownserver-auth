use chrono::prelude::*;
use chrono::Duration;
use magic_tunnel_auth::{make_jwt, decode_jwt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = "supersecretsharedpassphrased";
    let token = make_jwt(
        secret,
        Duration::minutes(10),
        "hoge-id".to_string(),
    );
    println!("token: {:?}", token);
    println!("decoded: {:?}", decode_jwt(secret, &token?));
    Ok(())
}
