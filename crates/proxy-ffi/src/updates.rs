//! Asynchronous update jobs. Each accepted job produces bounded progress events
//! followed by exactly one terminal event; strings use proxy_update_free_event_v1.
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

type Callback = extern "C" fn(u64, *mut c_char);

fn jobs() -> &'static Mutex<HashMap<u64, CancellationToken>> {
    static JOBS: OnceLock<Mutex<HashMap<u64, CancellationToken>>> = OnceLock::new();
    JOBS.get_or_init(Mutex::default)
}

fn event(callback: Callback, id: u64, value: Value) {
    // JSON escapes embedded NUL bytes, so conversion cannot fail.
    let string = CString::new(value.to_string()).expect("JSON contains no NUL");
    callback(id, string.into_raw());
}

fn progress_messages() -> &'static Mutex<HashMap<usize, Arc<AtomicBool>>> {
    static MESSAGES: OnceLock<Mutex<HashMap<usize, Arc<AtomicBool>>>> = OnceLock::new();
    MESSAGES.get_or_init(Mutex::default)
}

fn progress_event(callback: Callback, id: u64, value: Value, pending: &Arc<AtomicBool>) {
    // A suspended Flutter isolate must not accumulate progress notifications.
    // Keep at most one outstanding progress allocation per job; completion
    // always carries the final counters, even when intermediate samples coalesce.
    if pending.swap(true, Ordering::AcqRel) {
        return;
    }
    let string = CString::new(value.to_string())
        .expect("JSON contains no NUL")
        .into_raw();
    progress_messages()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(string as usize, pending.clone());
    callback(id, string);
}

/// Release one event allocated by proxy_update_start_v1 and return its progress
/// credit. Every callback string, including terminal events, needs this call.
///
/// # Safety
/// `message` must be null or an unreleased event from proxy_update_start_v1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_update_free_event_v1(message: *mut c_char) {
    if message.is_null() {
        return;
    }
    if let Some(pending) = progress_messages()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&(message as usize))
    {
        pending.store(false, Ordering::Release);
    }
    // SAFETY: the caller transfers the unique allocation back to its owner.
    drop(unsafe { CString::from_raw(message) });
}

/// Start a JSON update request. Returns 0 if rejected (invalid input, unavailable
/// runtime, or 8 active jobs). Accepted jobs always end with `complete` or `failed`.
/// The callback must remain callable until that terminal event; each string is
/// Rust-owned and must be released with proxy_update_free_event_v1.
///
/// # Safety
/// `request` must point to a NUL-terminated UTF-8 string for the duration of this
/// call. `callback` must safely accept calls from arbitrary native threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_update_start_v1(
    request: *const c_char,
    callback: Option<Callback>,
) -> u64 {
    std::panic::catch_unwind(|| {
        crate::init_process_policy();
        let Some(callback) = callback else { return 0 };
        if request.is_null() { return 0; }
        // SAFETY: guaranteed by the caller; all data is copied before returning.
        let bytes = unsafe { CStr::from_ptr(request) }.to_bytes();
        if bytes.len() > 3 * 1024 * 1024 { return 0; }
        let Ok(request) = serde_json::from_slice::<proxy_updater::transfer::Request>(bytes) else { return 0 };
        let Some(runtime) = crate::runtime::control() else { return 0 };
        let Ok(mut active) = jobs().lock() else { return 0 };
        if active.len() >= 8 { return 0; }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        active.insert(id, cancel.clone());
        drop(active);
        runtime.spawn(async move {
            let task = tokio::spawn(async move {
                let pending = Arc::new(AtomicBool::new(false));
                proxy_updater::transfer::execute(request, cancel, |progress| {
                    progress_event(callback, id, json!({"type": "progress", "data": progress}), &pending);
                }).await
            });
            let terminal = match task.await {
                Ok(Ok(data)) => json!({"type": "complete", "data": data}),
                Ok(Err(error)) => json!({"type": "failed", "kind": error.kind, "message": error.message}),
                Err(_) => json!({"type": "failed", "kind": "install", "message": "Native update task failed"}),
            };
            if let Ok(mut active) = jobs().lock() { active.remove(&id); }
            event(callback, id, terminal);
        });
        id
    }).unwrap_or(0)
}

/// Request cancellation; the terminal callback acknowledges completion and
/// cleanup. It is safe to cancel an already completed or unknown job.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_update_cancel_v1(id: u64) {
    if let Ok(active) = jobs().lock()
        && let Some(cancel) = active.get(&id)
    {
        cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static RETAINED: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    extern "C" fn retain(_: u64, message: *mut c_char) {
        RETAINED.lock().unwrap().push(message as usize);
    }
    #[test]
    fn suspended_ui_retains_at_most_one_progress_event_per_job() {
        let pending = Arc::new(AtomicBool::new(false));
        for received in 0..10_000 {
            progress_event(retain, 1, json!({"received": received}), &pending);
        }
        let mut messages = RETAINED.lock().unwrap();
        assert_eq!(messages.len(), 1);
        let message = messages.pop().unwrap() as *mut c_char;
        drop(messages);
        unsafe {
            proxy_update_free_event_v1(message);
        }
        assert!(!pending.load(Ordering::Acquire));
        progress_event(retain, 1, json!({"received": 10_000}), &pending);
        let message = RETAINED.lock().unwrap().pop().unwrap() as *mut c_char;
        unsafe {
            proxy_update_free_event_v1(message);
        }
    }
}
