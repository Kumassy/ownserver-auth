use ownserver_auth::build_routes;
use structopt::StructOpt;
use tracing::{warn, debug};

#[derive(StructOpt, Debug)]
#[structopt(name = "ownserver")]
struct Opt {
    #[structopt(long, default_value = "8123")]
    port: u16,

    #[structopt(long, env = "MT_TOKEN_SECRET")]
    token_secret: String,

    #[structopt(short, long)]
    hosts: Vec<String>,
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();
    debug!("{:?}", opt);

    if opt.hosts.is_empty() {
        warn!("No available host");
    }

    let Opt { token_secret, hosts, port } = opt;
    let routes = build_routes(token_secret, hosts);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
    Ok(())
}
