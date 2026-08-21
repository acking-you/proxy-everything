//! Process-wide file-descriptor limit policy.
//!
//! A proxy holds two descriptors per tunnelled connection plus one per listener
//! and upstream probe, so the descriptor table is the binding resource under
//! load. Unix soft limits are frequently far below what the hard limit already
//! permits, and a process may raise its own soft limit up to that hard limit
//! without any privilege. Doing so at startup turns an `EMFILE` outage into a
//! non-event.
//!
//! macOS is the platform that actually needs this. A GUI `.app` inherits
//! launchd's `maxfiles` (commonly 256) rather than the shell's much larger
//! value, which is why the CLI never hit the ceiling that the Flutter UI did.
//! Windows has no comparable per-process cap and is therefore left alone.

#[cfg(unix)]
use std::sync::OnceLock;

/// Descriptors this process asks for when the hard limit allows it.
///
/// Chosen to cover a full desktop workload — a browser alone can open hundreds
/// of concurrent flows, and each one costs two descriptors — while staying well
/// under the `kern.maxfilesperproc` values macOS ships with.
#[cfg(unix)]
const DESIRED_FILE_DESCRIPTORS: libc::rlim_t = 65_536;

#[cfg(unix)]
static APPLIED_LIMIT: OnceLock<Option<FileDescriptorLimit>> = OnceLock::new();

/// Outcome of one attempt to raise the soft descriptor limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDescriptorLimit {
    /// Soft limit observed before the adjustment.
    pub previous_soft: u64,
    /// Soft limit in effect afterwards.
    pub current_soft: u64,
    /// Hard ceiling the soft limit cannot exceed.
    pub hard: u64,
}

impl FileDescriptorLimit {
    /// Whether this call actually moved the soft limit.
    pub fn raised(&self) -> bool {
        self.current_soft > self.previous_soft
    }
}

/// Raise the soft descriptor limit toward [`DESIRED_FILE_DESCRIPTORS`], once per
/// process.
///
/// Returns the resulting limits, or `None` on platforms without a per-process
/// descriptor limit and when the limits cannot be read. Never fails the caller:
/// a process that cannot raise its limit should still start and serve traffic up
/// to whatever ceiling it has.
pub fn raise_file_descriptor_limit() -> Option<FileDescriptorLimit> {
    #[cfg(unix)]
    {
        *APPLIED_LIMIT.get_or_init(|| apply_file_descriptor_limit(DESIRED_FILE_DESCRIPTORS))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Raise the soft limit to `desired`, clamped to the current hard limit.
///
/// Separated from the `OnceLock` wrapper so tests can exercise the clamping logic
/// against the real limits without consuming the process-wide latch.
#[cfg(unix)]
fn apply_file_descriptor_limit(desired: libc::rlim_t) -> Option<FileDescriptorLimit> {
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `getrlimit` writes a complete `rlimit` for a valid resource id.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the call above succeeded and therefore initialized the value.
    let limits = unsafe { limits.assume_init() };

    let previous_soft = limits.rlim_cur;
    let hard = limits.rlim_max;
    // RLIM_INFINITY means the hard limit imposes no ceiling of its own, so the
    // desired value is always reachable.
    let target = if hard == libc::RLIM_INFINITY {
        desired
    } else {
        desired.min(hard)
    };

    if target <= previous_soft {
        return Some(FileDescriptorLimit {
            previous_soft,
            current_soft: previous_soft,
            hard,
        });
    }

    let requested = libc::rlimit {
        rlim_cur: target,
        rlim_max: limits.rlim_max,
    };
    // SAFETY: `requested` is a fully initialized `rlimit` whose soft limit does
    // not exceed the hard limit just read, which is what `setrlimit` requires.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &requested) } != 0 {
        return Some(FileDescriptorLimit {
            previous_soft,
            current_soft: previous_soft,
            hard,
        });
    }

    Some(FileDescriptorLimit {
        previous_soft,
        current_soft: target,
        hard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raising_is_idempotent_and_reports_the_effective_limit() {
        let first = raise_file_descriptor_limit();
        let second = raise_file_descriptor_limit();
        assert_eq!(first, second, "the limit must be latched for the process");

        #[cfg(unix)]
        {
            let limit = first.expect("unix platforms report descriptor limits");
            assert!(
                limit.current_soft >= limit.previous_soft,
                "the soft limit must never be lowered"
            );
            if limit.hard != libc::RLIM_INFINITY {
                assert!(
                    limit.current_soft <= limit.hard,
                    "the soft limit must stay within the hard ceiling"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_request_below_the_current_soft_limit_changes_nothing() {
        // Every Unix system allows at least this many descriptors, so the
        // request is guaranteed to be a no-op rather than a reduction.
        let limit = apply_file_descriptor_limit(1).expect("descriptor limits are readable");
        assert_eq!(limit.current_soft, limit.previous_soft);
        assert!(!limit.raised());
    }

    #[cfg(unix)]
    #[test]
    fn the_request_is_clamped_to_the_hard_ceiling() {
        let limit =
            apply_file_descriptor_limit(libc::rlim_t::MAX).expect("descriptor limits are readable");
        if limit.hard != libc::RLIM_INFINITY {
            assert!(limit.current_soft <= limit.hard);
        }
    }
}
