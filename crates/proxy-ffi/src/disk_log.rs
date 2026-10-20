//! Native diagnostics are persisted before UI filtering and callback throttling.
//! A bounded worker queue keeps file I/O off forwarding and Flutter threads.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

static SINK: Mutex<Option<DiskLog>> = Mutex::new(None);
const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 8;
const PREFIX: &str = "proxy-native-";

enum Command {
    Entry(String),
    Flush(mpsc::SyncSender<io::Result<()>>),
}

#[derive(Clone)]
struct DiskLog {
    directory: PathBuf,
    sender: mpsc::SyncSender<Command>,
    queued_bytes: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl DiskLog {
    fn new(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let mut files = LogFiles::new(directory.to_path_buf())?;
        let (sender, receiver) = mpsc::sync_channel(1024);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::clone(&queued_bytes);
        let lost = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("proxy-log-writer".into())
            .spawn(move || {
                let mut failed = false;
                loop {
                    let command = receiver.recv_timeout(Duration::from_millis(250));
                    let skipped = lost.swap(0, Ordering::Relaxed);
                    let result = (|| -> io::Result<()> {
                        if skipped > 0 {
                            files.write(&format!(
                                "{} WARN native disk queue overflow: {skipped} entries lost\n",
                                chrono::Local::now().to_rfc3339()
                            ))?;
                        }
                        match &command {
                            Ok(Command::Entry(line)) => files.write(line),
                            _ => files.writer.flush(),
                        }
                    })();
                    if let Ok(Command::Entry(line)) = &command {
                        bytes.fetch_sub(line.len(), Ordering::Relaxed);
                    }
                    if let Err(error) = &result {
                        // Never feed writer failures back into the same queue.
                        eprintln!("native log persistence failed: {error}");
                        if !failed {
                            crate::logging::send_callback(
                                4,
                                &format!("Native log persistence failed: {error}"),
                            );
                        }
                        failed = true;
                    } else if failed {
                        crate::logging::send_callback(
                            3,
                            "Native log persistence recovered; records may have been lost during \
                             the disk failure",
                        );
                        failed = false;
                    }
                    if let Ok(Command::Flush(done)) = &command {
                        let _ = done.send(result);
                    }
                    if matches!(command, Err(mpsc::RecvTimeoutError::Disconnected)) {
                        break;
                    }
                }
            })?;
        Ok(Self {
            directory: directory.into(),
            sender,
            queued_bytes,
            dropped,
        })
    }

    fn write(&self, level: i32, message: &str) {
        self.write_at(level, message, chrono::Local::now());
    }

    fn write_at(&self, level: i32, message: &str, timestamp: chrono::DateTime<chrono::Local>) {
        let level = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"][level.clamp(0, 4) as usize];
        let line = format!("{} {level} {message}\n", timestamp.to_rfc3339());
        let length = line.len();
        if self
            .queued_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |bytes| {
                (length <= MAX_QUEUED_BYTES.saturating_sub(bytes)).then_some(bytes + length)
            })
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.sender.try_send(Command::Entry(line)).is_err() {
            self.queued_bytes.fetch_sub(length, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) -> io::Result<()> {
        let (done, received) = mpsc::sync_channel(1);
        // Shutdown is the only blocking producer: enqueue the barrier even
        // when the data queue is full, then wait for the worker's flush result.
        self.sender
            .send(Command::Flush(done))
            .map_err(io::Error::other)?;
        received.recv().map_err(io::Error::other)?
    }
}

struct LogFiles {
    directory: PathBuf,
    writer: BufWriter<File>,
    lease: File,
    bytes: u64,
    sequence: u64,
}

impl LogFiles {
    fn new(directory: PathBuf) -> io::Result<Self> {
        let _directory_lock = Self::lock_directory(&directory)?;
        let (writer, lease, sequence) = Self::open(&directory, 0)?;
        let mut files = Self {
            directory,
            writer,
            lease,
            bytes: 0,
            sequence,
        };
        files.cleanup()?;
        Ok(files)
    }

    fn lock_directory(directory: &Path) -> io::Result<File> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(".proxy-native.lock"))?;
        // Serialize creation and cleanup so a new log cannot be removed before
        // its lifetime lock is acquired. Dropping the handle releases the lock.
        lock.lock()?;
        Ok(lock)
    }

    fn open(directory: &Path, mut sequence: u64) -> io::Result<(BufWriter<File>, File, u64)> {
        loop {
            let name = format!(
                "{PREFIX}{}-{}-{sequence:04}.log",
                chrono::Local::now().format("%Y%m%d-%H%M%S"),
                std::process::id()
            );
            let path = directory.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    // Lock a sidecar, so diagnostics remain readable on
                    // Windows where byte-range locks also exclude readers.
                    let lease = Self::open_lease(&path)?;
                    lease.lock()?;
                    return Ok((BufWriter::new(file), lease, sequence));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => sequence += 1,
                Err(error) => return Err(error),
            }
        }
    }

    fn open_lease(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("log.lock"))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let mut files = fs::read_dir(&self.directory)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(PREFIX)
                    && name.ends_with(".log")
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
            })
            .collect::<Vec<_>>();
        files.sort_by_key(|entry| {
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
        });
        let mut remaining = files.len();
        for entry in files {
            if remaining <= MAX_FILES {
                break;
            }
            let Ok(lease) = Self::open_lease(&entry.path()) else {
                continue;
            };
            // Windows, Linux and macOS all keep this exclusive lock while the
            // owning worker writes. Never unlink another live writer's file.
            if lease.try_lock().is_ok() && fs::remove_file(entry.path()).is_ok() {
                let _ = fs::remove_file(entry.path().with_extension("log.lock"));
                remaining -= 1;
            }
        }
        Ok(())
    }

    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.bytes + line.len() as u64 > MAX_FILE_BYTES {
            let _directory_lock = Self::lock_directory(&self.directory)?;
            self.writer.flush()?;
            (self.writer, self.lease, self.sequence) =
                Self::open(&self.directory, self.sequence + 1)?;
            self.bytes = 0;
            self.cleanup()?;
        }
        self.writer.write_all(line.as_bytes())?;
        self.bytes += line.len() as u64;
        Ok(())
    }
}

pub(crate) fn configure(directory: &Path) -> io::Result<()> {
    let mut sink = SINK.lock().unwrap_or_else(|error| error.into_inner());
    if sink
        .as_ref()
        .is_some_and(|sink| sink.directory == directory)
    {
        return Ok(());
    }
    *sink = Some(DiskLog::new(directory)?);
    Ok(())
}

pub(crate) fn write(level: i32, message: &str) {
    if let Some(sink) = SINK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
    {
        sink.write(level, message);
    }
}

pub(crate) fn flush() {
    if let Err(error) = flush_result() {
        eprintln!("native log flush failed: {error}");
        crate::logging::send_callback(4, &format!("Native log flush failed: {error}"));
    }
}

pub(crate) fn flush_result() -> io::Result<()> {
    let sink = SINK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .cloned();
    // Never hold the global producer lock while waiting on I/O or callbacks.
    sink.map_or(Ok(()), |sink| sink.flush())
}

/// Append a UI diagnostic to the same bounded native writer without echoing it
/// through the native log callback (which would duplicate it in the UI).
///
/// # Safety
/// `message` must be a valid NUL-terminated UTF-8 string during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_log_write_v1(
    level: i32,
    message: *const std::ffi::c_char,
    timestamp_ms: i64,
) -> i32 {
    if message.is_null() {
        return -1;
    }
    let Ok(message) = (unsafe { std::ffi::CStr::from_ptr(message) }).to_str() else {
        return -1;
    };
    let timestamp = chrono::DateTime::from_timestamp_millis(timestamp_ms)
        .map(|value| value.with_timezone(&chrono::Local))
        .unwrap_or_else(chrono::Local::now);
    let sink = SINK.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(sink) = sink.as_ref() {
        sink.write_at(level, &format!("[ui] {message}"), timestamp);
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_flush_waits_for_a_full_queue_and_the_worker() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender.send(Command::Entry("queued record".into())).unwrap();
        let sink = DiskLog {
            directory: PathBuf::new(),
            sender,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        };
        let (started, start) = mpsc::sync_channel(1);
        let (finished, finish) = mpsc::sync_channel(1);
        let flush = std::thread::spawn(move || {
            started.send(()).unwrap();
            let result = sink.flush();
            finished.send(()).unwrap();
            result
        });
        start.recv().unwrap();
        assert!(finish.recv_timeout(Duration::from_millis(25)).is_err());
        assert!(matches!(receiver.recv().unwrap(), Command::Entry(_)));
        let Command::Flush(done) = receiver.recv_timeout(Duration::from_secs(1)).unwrap() else {
            panic!("missing flush barrier");
        };
        assert!(finish.try_recv().is_err());
        done.send(Ok(())).unwrap();
        flush.join().unwrap().unwrap();
    }

    #[test]
    fn native_retention_keeps_live_files_readable_and_removes_closed_files() {
        let directory = std::env::temp_dir().join(format!(
            "proxy-retention-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut live = Vec::new();
        for _ in 0..MAX_FILES + 1 {
            let mut files = LogFiles::new(directory.clone()).unwrap();
            files.write("live diagnostics\n").unwrap();
            files.writer.flush().unwrap();
            live.push(files);
        }
        let log_paths = || {
            fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
                .collect::<Vec<_>>()
        };
        let paths = log_paths();
        assert_eq!(paths.len(), MAX_FILES + 1);
        for path in &paths {
            assert_eq!(fs::read_to_string(path).unwrap(), "live diagnostics\n");
        }
        drop(live);
        let files = LogFiles::new(directory.clone()).unwrap();
        assert_eq!(log_paths().len(), MAX_FILES);
        drop(files);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_disk_keeps_complete_records_independently_of_the_ui() {
        let directory = std::env::temp_dir().join(format!(
            "proxy-log-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let sink = DiskLog::new(&directory).unwrap();
        for i in 0..100 {
            sink.write(
                2,
                &format!("CONNECT example.test:443 request={i} 中文\nCaused by: connection reset"),
            );
        }
        sink.flush().unwrap();
        let file = fs::read_dir(&directory)
            .unwrap()
            .find(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.path().extension().is_some_and(|ext| ext == "log"))
            })
            .unwrap()
            .unwrap()
            .path();
        let text = fs::read_to_string(file).unwrap();
        assert_eq!(text.matches("CONNECT example.test:443").count(), 100);
        assert!(text.contains("request=99 中文\nCaused by: connection reset"));
        drop(sink);
        // The worker owns the open file until its disconnected receive flushes.
        for _ in 0..100 {
            if fs::remove_dir_all(&directory).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("log worker did not release its files");
    }
}
