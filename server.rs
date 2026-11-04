// bin/server.rs — Standalone C2 Server binary
// Compile: cargo build --bin server
// Run:     cargo run --bin server -- --port 443 --dash 8080

use c2_toolkit::server_main;

#[tokio::main]
async fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();

    println!();
    println!("  ████████████████████████████████████████████████");
    println!("  █         C2 SERVER — Standalone Build         █");
    println!("  ████████████████████████████████████████████████");
    println!();

    server_main::run(args).await;
}
