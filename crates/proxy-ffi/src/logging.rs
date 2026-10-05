//! Logging system for FFI interface.

use std::collections::HashSet;
use std::ffi::{CString, c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use crate::types::LogCallback;

/// Global log callback
pub(crate) static LOG_CALLBACK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static MIN_LOG_LEVEL: AtomicU8 = AtomicU8::new(2);
static CALLBACK_RATE_LIMITER: Mutex<CallbackRateLimiter> = Mutex::new(CallbackRateLimiter::new());

const MAX_CALLBACK_EVENTS_PER_SECOND: u32 = 512;
const MAX_CRITICAL_EVENTS_PER_SECOND: u32 = 64;
const MAX_CALLBACK_MESSAGE_BYTES: usize = 8192;
const MAX_PENDING_CALLBACKS: usize = 1024;
static LOG_ALLOCATIONS: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static LOG_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

#[derive(Debug)]
struct CallbackRateLimiter {
    second: u64,
    emitted: u32,
    critical: u32,
    dropped: u64,
}

impl CallbackRateLimiter {
    const fn new() -> Self {
        Self {
            second: 0,
            emitted: 0,
            critical: 0,
            dropped: 0,
        }
    }

    fn decide(&mut self, second: u64, level: c_int) -> (bool, u64) {
        let dropped = if self.second == second {
            0
        } else {
            self.second = second;
            self.emitted = 0;
            self.critical = 0;
            std::mem::take(&mut self.dropped)
        };

        // Reserve room for failures, but a repeated failure must not flood the
        // cross-isolate queue any more than per-packet debug messages can.
        let count = if level >= 3 {
            &mut self.critical
        } else {
            &mut self.emitted
        };
        let limit = if level >= 3 {
            MAX_CRITICAL_EVENTS_PER_SECOND
        } else {
            MAX_CALLBACK_EVENTS_PER_SECOND
        };
        if *count < limit {
            *count += 1;
            (true, dropped)
        } else {
            self.dropped = self.dropped.saturating_add(1);
            (false, dropped)
        }
    }
}

/// Internal function to send log to callback
pub(crate) fn send_log(level: c_int, message: &str) {
    if LOG_CALLBACK.load(Ordering::Relaxed).is_null() {
        return;
    }
    let (forward, dropped) = CALLBACK_RATE_LIMITER
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .decide(LOG_EPOCH.elapsed().as_secs(), level);
    if dropped > 0 {
        deliver_log(
            3,
            &format!(
                "[proxy_ffi::logging] suppressed {dropped} log entries in the previous second to \
                 bound UI work"
            ),
        );
    }
    if forward {
        deliver_log(level, message);
    }
}

fn allocate_log_message(message: &str) -> Option<*mut c_char> {
    let mut pending = LOG_ALLOCATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if pending.len() >= MAX_PENDING_CALLBACKS {
        return None;
    }
    let mut end = message.len().min(MAX_CALLBACK_MESSAGE_BYTES);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let message = CString::new(&message[..end]).ok()?.into_raw();
    pending.insert(message as usize);
    Some(message)
}

fn deliver_log(level: c_int, message: &str) {
    let ptr = LOG_CALLBACK.load(Ordering::SeqCst);
    if ptr.is_null() {
        return;
    }
    if let Some(message) = allocate_log_message(message) {
        let callback: LogCallback = unsafe { std::mem::transmute(ptr) };
        callback(level, message);
    } else {
        let mut limiter = CALLBACK_RATE_LIMITER
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        limiter.dropped = limiter.dropped.saturating_add(1);
    }
}

/// Set log callback function.
///
/// # Safety
/// `callback` must be a valid function pointer or null to disable logging.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_set_log_callback(callback: Option<LogCallback>) {
    let ptr = callback.map(|f| f as *mut ()).unwrap_or(ptr::null_mut());
    LOG_CALLBACK.store(ptr, Ordering::SeqCst);
}

/// Set the minimum level delivered to the FFI callback.
///
/// Levels use the stable callback ABI: 0=trace, 1=debug, 2=info, 3=warn,
/// 4=error. Values outside that range are clamped. The default is info.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_set_log_level(level: c_int) {
    MIN_LOG_LEVEL.store(level.clamp(0, 4) as u8, Ordering::Relaxed);
}

/// Free a string allocated by the library (e.g., from log callback).
///
/// # Safety
/// `s` must be a valid pointer returned from a log callback, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_string(s: *mut c_char) {
    if !s.is_null() {
        LOG_ALLOCATIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&(s as usize));
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Custom tracing layer that forwards logs to FFI callback
pub(crate) struct FfiLogLayer;

impl<S> tracing_subscriber::Layer<S> for FfiLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            tracing::Level::TRACE => 0,
            tracing::Level::DEBUG => 1,
            tracing::Level::INFO => 2,
            tracing::Level::WARN => 3,
            tracing::Level::ERROR => 4,
        };
        if level < MIN_LOG_LEVEL.load(Ordering::Relaxed) as c_int
            || LOG_CALLBACK.load(Ordering::Relaxed).is_null()
        {
            return;
        }

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = format!(
            "[{}] {}",
            event.metadata().target(),
            visitor.message.unwrap_or_default()
        );
        send_log(level, &message);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        } else if self.message.is_none() {
            self.message = Some(format!("{}: {:?}", field.name(), value));
        } else if let Some(msg) = self.message.take() {
            self.message = Some(format!("{}, {}: {:?}", msg, field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else if self.message.is_none() {
            self.message = Some(format!("{}: {}", field.name(), value));
        } else if let Some(msg) = self.message.take() {
            self.message = Some(format!("{}, {}: {}", msg, field.name(), value));
        }
    }
}

/// Initialize logging with FFI callback support.
///
/// # Safety
/// Can be called multiple times safely.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_init_logging() {
    crate::init_process_policy();
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(FfiLogLayer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive("http_proxy=info".parse().expect("valid directive")),
                ),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_stalled_ui_cannot_accumulate_unbounded_native_log_strings() {
        let mut pointers = Vec::new();
        for _ in 0..super::MAX_PENDING_CALLBACKS {
            pointers.push(super::allocate_log_message(&"界".repeat(4000)).unwrap());
        }
        assert!(super::allocate_log_message("overflow").is_none());
        let value = unsafe { std::ffi::CStr::from_ptr(pointers[0]) };
        assert!(value.to_str().is_ok());
        assert!(value.to_bytes().len() <= super::MAX_CALLBACK_MESSAGE_BYTES);
        for pointer in pointers {
            unsafe { super::proxy_free_string(pointer) };
        }
        let recovered = super::allocate_log_message("recovered").unwrap();
        unsafe { super::proxy_free_string(recovered) };
    }

    #[test]
    fn error_storms_are_bounded_and_reported_in_the_next_window() {
        let mut limiter = super::CallbackRateLimiter::new();
        for _ in 0..super::MAX_CRITICAL_EVENTS_PER_SECOND {
            assert!(limiter.decide(10, 4).0);
        }
        for _ in 0..10_000 {
            assert!(!limiter.decide(10, 4).0);
        }
        assert_eq!(limiter.decide(11, 3), (true, 10_000));
        assert_eq!(limiter.decide(11, 3), (true, 0));
    }

    use super::*;

    #[test]
    fn callback_rate_limit_bounds_low_priority_bursts() {
        let mut limiter = CallbackRateLimiter::new();
        for _ in 0..MAX_CALLBACK_EVENTS_PER_SECOND {
            assert_eq!(limiter.decide(10, 2), (true, 0));
        }
        assert_eq!(limiter.decide(10, 2), (false, 0));
        assert_eq!(limiter.decide(10, 4), (true, 0));

        let (forward, dropped) = limiter.decide(11, 2);
        assert!(forward);
        assert_eq!(dropped, 1);
    }
}
