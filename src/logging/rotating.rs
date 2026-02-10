use flate2::write::GzEncoder;
use flate2::Compression;
use std::cmp::Reverse;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub(super) struct RotatingMakeWriter {
    inner: Arc<Mutex<RotatingInner>>,
}

impl RotatingMakeWriter {
    pub(super) fn new(
        output: PathBuf,
        rotate_max_size_bytes: u64,
        rotate_keep_files: usize,
        compress: bool,
    ) -> io::Result<Self> {
        let (file, size) = open_append(&output)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(RotatingInner {
                output,
                file,
                size,
                rotate_max_size_bytes: rotate_max_size_bytes.max(1),
                rotate_keep_files,
                compress,
            })),
        })
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for RotatingMakeWriter {
    type Writer = RotatingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingWriter {
            inner: self.inner.clone(),
        }
    }
}

pub(super) struct RotatingWriter {
    inner: Arc<Mutex<RotatingInner>>,
}

impl Write for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().expect("logging mutex poisoned");

        // Rotate before writing so a single large write doesn't overshoot too much.
        if inner.size.saturating_add(buf.len() as u64) >= inner.rotate_max_size_bytes {
            inner.rotate()?;
        }

        let n = inner.file.write(buf)?;
        inner.size = inner.size.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("logging mutex poisoned");
        inner.file.flush()
    }
}

struct RotatingInner {
    output: PathBuf,
    file: File,
    size: u64,
    rotate_max_size_bytes: u64,
    rotate_keep_files: usize,
    compress: bool,
}

impl RotatingInner {
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        let ts = utc_timestamp_compact(SystemTime::now());
        let rotated = rotated_path(&self.output, &ts);

        // Best-effort: if rename fails (e.g. different mount), fall back to copy+truncate.
        if fs::rename(&self.output, &rotated).is_err() {
            fs::copy(&self.output, &rotated)?;
            self.file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&self.output)?;
            self.size = 0;
        } else {
            let (file, size) = open_append(&self.output)?;
            self.file = file;
            self.size = size;
        }

        if self.compress {
            spawn_compress(rotated.clone());
        }

        self.cleanup_old_files()?;
        Ok(())
    }

    fn cleanup_old_files(&self) -> io::Result<()> {
        let Some(dir) = self.output.parent() else {
            return Ok(());
        };

        let Some((base, ext)) = base_and_ext(&self.output) else {
            return Ok(());
        };

        let mut rotated = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            // Match: base.TIMESTAMP.ext (and compressed variant ext.gz)
            if !name.starts_with(&format!("{base}.")) {
                continue;
            }

            let want_ext = format!(".{ext}");
            if !(name.ends_with(&want_ext) || name.ends_with(&format!("{want_ext}.gz"))) {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            rotated.push((modified, path));
        }

        rotated.sort_by_key(|(t, _)| Reverse(*t));

        let keep = self.rotate_keep_files;
        if keep == 0 {
            for (_, path) in rotated {
                let _ = fs::remove_file(path);
            }
            return Ok(());
        }

        for (_, path) in rotated.into_iter().skip(keep) {
            let _ = fs::remove_file(path);
        }

        Ok(())
    }
}

fn open_append(path: &Path) -> io::Result<(File, u64)> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            let _ = fs::create_dir_all(dir);
        }
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((file, size))
}

fn rotated_path(output: &Path, ts: &str) -> PathBuf {
    let dir = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("arkime-rust");
    let ext = output.extension().and_then(|s| s.to_str()).unwrap_or("log");
    dir.join(format!("{stem}.{ts}.{ext}"))
}

fn base_and_ext(output: &Path) -> Option<(String, String)> {
    let stem = output.file_stem()?.to_str()?.to_string();
    let ext = output.extension()?.to_str()?.to_string();
    Some((stem, ext))
}

fn spawn_compress(rotated: PathBuf) {
    std::thread::spawn(move || {
        let _ = gzip_file(&rotated);
    });
}

fn gzip_file(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
    let gz_path = path.with_extension(format!("{ext}.gz"));

    let in_file = File::open(path)?;
    let out_file = File::create(&gz_path)?;

    let mut reader = BufReader::new(in_file);
    let writer = BufWriter::new(out_file);
    let mut encoder = GzEncoder::new(writer, Compression::default());

    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?; // flush gzip stream

    let _ = fs::remove_file(path);
    Ok(())
}

fn utc_timestamp_compact(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs() as i64;
    unix_seconds_to_utc_compact(secs)
}

// UTC time formatting without external crates.
// Uses a civil-from-days conversion (Howard Hinnant) to get YYYYMMDD and then HHMMSS.
fn unix_seconds_to_utc_compact(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = (sod / 3600) as i64;
    let mm = ((sod % 3600) / 60) as i64;
    let ss = (sod % 60) as i64;
    format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Convert days since 1970-01-01 to Gregorian Y-M-D in UTC.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365); // [0,399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0,365]
    let mp = (5 * doy + 2).div_euclid(153); // [0,11]
    let d = doy - (153 * mp + 2).div_euclid(5) + 1; // [1,31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1,12]
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}
