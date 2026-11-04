// main.rs — Default binary (all modules combined)
// Use `cargo run --bin server` for server-only
// Use `cargo run --bin client` for agent-only

fn main() {
    env_logger::init();
    println!("C2 Toolkit — Rust Edition");
    println!();
    println!("  Compile targets:");
    println!("    cargo build --bin server   — C2 Server only");
    println!("    cargo build --bin client   — C2 Agent only");
    println!("    cargo build --bin c2_toolkit — Everything");
    println!();
    println!("  Run targets:");
    println!("    cargo run --bin server -- --port 443 --dash 8080");
    println!("    cargo run --bin client");
}
