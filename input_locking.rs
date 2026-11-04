// input_locking.rs — Rust port of Input Locking.cs (InputLocker)
// Blocks keyboard/mouse input on Windows using BlockInput and low-level hooks.
// On non-Windows platforms, provides stub implementations.

use std::sync::atomic::{AtomicBool, Ordering};
use log::{info, warn};

static IS_LOCKED: AtomicBool = AtomicBool::new(false);

pub struct InputLocker;

impl InputLocker {
    /// Blocks all keyboard and mouse input.
    /// On Windows, uses BlockInput + low-level hooks.
    /// Requires the calling process to run with admin privileges.
    pub fn lock_input() {
        if IS_LOCKED.load(Ordering::Relaxed) {
            info!("Input already locked.");
            return;
        }

        #[cfg(target_os = "windows")]
        {
            unsafe {
                // BlockInput(TRUE) — blocks physical keyboard/mouse
                let result = BlockInput(1);
                if result != 0 {
                    IS_LOCKED.store(true, Ordering::Relaxed);
                    info!("[+] Input locked via BlockInput.");
                } else {
                    warn!("[-] BlockInput failed (need admin).");
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            warn!("InputLocker: BlockInput is Windows-only.");
            IS_LOCKED.store(true, Ordering::Relaxed);
        }
    }

    /// Unblocks all keyboard and mouse input.
    pub fn unlock_input() {
        if !IS_LOCKED.load(Ordering::Relaxed) {
            return;
        }

        #[cfg(target_os = "windows")]
        {
            unsafe {
                BlockInput(0);
                info!("[+] Input unlocked.");
            }
        }

        IS_LOCKED.store(false, Ordering::Relaxed);
    }

    /// Returns whether input is currently locked.
    pub fn is_locked() -> bool {
        IS_LOCKED.load(Ordering::Relaxed)
    }

    /// Locks input for a specified duration, then automatically unlocks.
    pub async fn lock_for_duration(duration_secs: u64) {
        Self::lock_input();
        tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
        Self::unlock_input();
        info!("[+] Input auto-unlocked after {}s.", duration_secs);
    }
}

// ==================== Windows P/Invoke ====================

#[cfg(target_os = "windows")]
extern "system" {
    fn BlockInput(fBlockIt: i32) -> i32;
}

// ==================== Low-Level Hooks (Windows) ====================

#[cfg(target_os = "windows")]
pub mod hooks {
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};

    const WH_KEYBOARD_LL: i32 = 13;
    const WH_MOUSE_LL: i32 = 14;

    static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);
    static mut KEYBOARD_HOOK: usize = 0;
    static mut MOUSE_HOOK: usize = 0;

    type HOOKPROC = unsafe extern "system" fn(i32, usize, usize) -> usize;

    extern "system" {
        fn SetWindowsHookExW(
            id_hook: i32,
            lpfn: HOOKPROC,
            h_mod: usize,
            dw_thread_id: u32,
        ) -> usize;
        fn UnhookWindowsHookEx(hhk: usize) -> i32;
        fn CallNextHookEx(hhk: usize, n_code: i32, w_param: usize, l_param: usize) -> usize;
        fn GetModuleHandleW(lp_module_name: *const u16) -> usize;
    }

    /// Low-level keyboard hook callback — swallows all keys.
    unsafe extern "system" fn keyboard_hook_proc(
        n_code: i32,
        w_param: usize,
        l_param: usize,
    ) -> usize {
        if n_code >= 0 {
            return 1; // Swallow the keystroke
        }
        CallNextHookEx(KEYBOARD_HOOK, n_code, w_param, l_param)
    }

    /// Low-level mouse hook callback — swallows all mouse events.
    unsafe extern "system" fn mouse_hook_proc(
        n_code: i32,
        w_param: usize,
        l_param: usize,
    ) -> usize {
        if n_code >= 0 {
            return 1; // Swallow the mouse event
        }
        CallNextHookEx(MOUSE_HOOK, n_code, w_param, l_param)
    }

    /// Install low-level keyboard and mouse hooks.
    pub fn install_hooks() {
        if HOOKS_INSTALLED.load(Ordering::Relaxed) {
            return;
        }

        unsafe {
            let h_mod = GetModuleHandleW(ptr::null());

            KEYBOARD_HOOK = SetWindowsHookExW(WH_KEYBOARD_LL, keyboard_hook_proc, h_mod, 0);
            MOUSE_HOOK = SetWindowsHookExW(WH_MOUSE_LL, mouse_hook_proc, h_mod, 0);

            if KEYBOARD_HOOK != 0 && MOUSE_HOOK != 0 {
                HOOKS_INSTALLED.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Remove low-level hooks.
    pub fn remove_hooks() {
        if !HOOKS_INSTALLED.load(Ordering::Relaxed) {
            return;
        }

        unsafe {
            if KEYBOARD_HOOK != 0 {
                UnhookWindowsHookEx(KEYBOARD_HOOK);
                KEYBOARD_HOOK = 0;
            }
            if MOUSE_HOOK != 0 {
                UnhookWindowsHookEx(MOUSE_HOOK);
                MOUSE_HOOK = 0;
            }
            HOOKS_INSTALLED.store(false, Ordering::Relaxed);
        }
    }
}
