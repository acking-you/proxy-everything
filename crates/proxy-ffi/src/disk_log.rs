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
    Flush(mpsc::SyncSender<()>),
}

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
                    if let Err(error) = result {
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
                        let _ = done.send(());
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
        let level = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"][level.clamp(0, 4) as usize];
        let line = format!("{} {level} {message}\n", chrono::Local::now().to_rfc3339());
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

    fn flush(&self) {
        let (done, received) = mpsc::sync_channel(1);
        if self.sender.try_send(Command::Flush(done)).is_ok() {
            let _ = received.recv_timeout(Duration::from_secs(1));
        }
    }
}

struct LogFiles {
    directory: PathBuf,
    writer: BufWriter<File>,
    bytes: u64,
    sequence: u64,
}

impl LogFiles {
    fn new(directory: PathBuf) -> io::Result<Self> {
        let (writer, sequence) = Self::open(&directory, 0)?;
        let mut files = Self {
            directory,
            writer,
            bytes: 0,
            sequence,
        };
        files.cleanup()?;
        Ok(files)
    }

    fn open(directory: &Path, mut sequence: u64) -> io::Result<(BufWriter<File>, u64)> {
        loop {
            let name = format!(
                "{PREFIX}{}-{}-{sequence:04}.log",
                chrono::Local::now().format("%Y%m%d-%H%M%S"),
                std::process::id()
            );
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))
            {
                Ok(file) => return Ok((BufWriter::new(file), sequence)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => sequence += 1,
                Err(error) => return Err(error),
            }
        }
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
        for entry in files.iter().take(files.len().saturating_sub(MAX_FILES)) {
            // Another running instance may still hold an older file open.
            let _ = fs::remove_file(entry.path());
        }
        Ok(())
    }

    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.bytes + line.len() as u64 > MAX_FILE_BYTES {
            self.writer.flush()?;
            (self.writer, self.sequence) = Self::open(&self.directory, self.sequence + 1)?;
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
    if let Some(sink) = SINK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
    {
        sink.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        sink.flush();
        let file = fs::read_dir(&directory)
            .unwrap()
            .next()
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
