//! Logging system for FFI interface.

use std::ffi::{CString, c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::types::LogCallback;

/// Global log callback
pub(crate) static LOG_CALLBACK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Internal function to send log to callback
pub(crate) fn send_log(level: c_int, message: &str) {
    let ptr = LOG_CALLBACK.load(Ordering::SeqCst);
    if !ptr.is_null()
        && let Ok(c_msg) = CString::new(message)
    {
        let callback: LogCallback = unsafe { std::mem::transmute(ptr) };
        let leaked = c_msg.into_raw();
        callback(level, leaked);
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

/// Free a string allocated by the library (e.g., from log callback).
///
/// # Safety
/// `s` must be a valid pointer returned from a log callback, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_string(s: *mut c_char) {
    if !s.is_null() {
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
