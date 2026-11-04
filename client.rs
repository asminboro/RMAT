// bin/client.rs — Standalone C2 Agent/Client binary
// Compile: cargo build --bin client
// Run:     cargo run --bin client

use c2_toolkit::main_program;

#[tokio::main]
async fn main() {
    env_logger::init();
    main_program::run().await;
}
