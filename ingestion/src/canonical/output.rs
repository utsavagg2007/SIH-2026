use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::canonical::CanonicalObservation;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum CanonicalOutputError {
    InvalidTarget(PathBuf),
    ParentUnavailable(PathBuf),
    TargetExists(PathBuf),
    ConcurrentWriter(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Serialization(serde_json::Error),
    PublishedButDurabilityUnconfirmed {
        path: PathBuf,
        operation: &'static str,
        source: std::io::Error,
    },
    PublishedButCleanupIncomplete {
        path: PathBuf,
        companion: PathBuf,
        operation: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for CanonicalOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(path) => {
                write!(f, "invalid canonical output target: {}", path.display())
            }
            Self::ParentUnavailable(path) => write!(
                f,
                "canonical output parent directory is unavailable: {}",
                path.display()
            ),
            Self::TargetExists(path) => write!(
                f,
                "canonical output already exists and will not be overwritten: {}",
                path.display()
            ),
            Self::ConcurrentWriter(path) => write!(
                f,
                "another canonical writer has reserved target: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "failed to {operation} {}: {source}", path.display()),
            Self::Serialization(source) => {
                write!(f, "failed to serialize canonical observation: {source}")
            }
            Self::PublishedButDurabilityUnconfirmed {
                path,
                operation,
                source,
            } => write!(
                f,
                "canonical artifact was published completely at {}, but {operation} failed; durability confirmation is unavailable: {source}",
                path.display()
            ),
            Self::PublishedButCleanupIncomplete {
                path,
                companion,
                operation,
                source,
            } => write!(
                f,
                "canonical artifact was published completely at {}, but {operation} failed for {}; manual companion cleanup may be required: {source}",
                path.display(),
                companion.display()
            ),
        }
    }
}

impl std::error::Error for CanonicalOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::PublishedButDurabilityUnconfirmed { source, .. }
            | Self::PublishedButCleanupIncomplete { source, .. } => Some(source),
            Self::Serialization(source) => Some(source),
            _ => None,
        }
    }
}

struct CleanupFile {
    path: PathBuf,
    armed: bool,
}

impl CleanupFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputCheckpoint {
    AfterJsonWrite,
    BeforePublish,
}

trait OutputHooks {
    fn create_temp(&self, path: &Path) -> std::io::Result<File> {
        open_new_temp(path)
    }

    fn checkpoint(
        &self,
        _checkpoint: OutputCheckpoint,
        _target: &Path,
        _temp: Option<&Path>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn flush_temp(&self, writer: &mut BufWriter<File>) -> std::io::Result<()> {
        writer.flush()
    }

    fn sync_temp(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn publish(&self, temp: &Path, target: &Path) -> std::io::Result<()> {
        fs::hard_link(temp, target)
    }

    fn sync_parent(&self, parent: &Path) -> std::io::Result<()> {
        sync_parent_directory(parent)
    }

    fn remove_published_temp(&self, path: &Path) -> std::io::Result<()> {
        fs::remove_file(path)
    }

    fn remove_lock(&self, path: &Path) -> std::io::Result<()> {
        fs::remove_file(path)
    }
}

struct NoopOutputHooks;

impl OutputHooks for NoopOutputHooks {}

fn open_new_temp(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> CanonicalOutputError {
    CanonicalOutputError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn serialization_or_write_error(path: &Path, source: serde_json::Error) -> CanonicalOutputError {
    if source.is_io() {
        let kind = source.io_error_kind().unwrap_or(std::io::ErrorKind::Other);
        io_error(
            "write temporary canonical output",
            path,
            std::io::Error::new(kind, source),
        )
    } else {
        CanonicalOutputError::Serialization(source)
    }
}

fn published_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> CanonicalOutputError {
    CanonicalOutputError::PublishedButDurabilityUnconfirmed {
        path: path.to_path_buf(),
        operation,
        source,
    }
}

fn published_cleanup_error(
    operation: &'static str,
    target: &Path,
    companion: &Path,
    source: std::io::Error,
) -> CanonicalOutputError {
    CanonicalOutputError::PublishedButCleanupIncomplete {
        path: target.to_path_buf(),
        companion: companion.to_path_buf(),
        operation,
        source,
    }
}

fn companion_path(target: &Path, suffix: &str) -> Result<PathBuf, CanonicalOutputError> {
    let Some(file_name) = target.file_name() else {
        return Err(CanonicalOutputError::InvalidTarget(target.to_path_buf()));
    };
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(suffix);
    Ok(target.with_file_name(name))
}

fn create_unique_temp<H: OutputHooks>(
    target: &Path,
    hooks: &H,
) -> Result<(File, CleanupFile), CanonicalOutputError> {
    for _ in 0..1000 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!(".canonical.{}.{sequence}.tmp", std::process::id());
        let temp_path = companion_path(target, &suffix)?;
        match hooks.create_temp(&temp_path) {
            Ok(file) => return Ok((file, CleanupFile::new(temp_path))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create temporary file", &temp_path, source)),
        }
    }
    Err(CanonicalOutputError::InvalidTarget(target.to_path_buf()))
}

fn write_jsonl_atomically_with_hooks<T: Serialize, H: OutputHooks>(
    target: &Path,
    values: &[T],
    hooks: &H,
) -> Result<(), CanonicalOutputError> {
    if target.file_name().is_none() {
        return Err(CanonicalOutputError::InvalidTarget(target.to_path_buf()));
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(CanonicalOutputError::ParentUnavailable(
            parent.to_path_buf(),
        ));
    }
    if target.exists() {
        return Err(CanonicalOutputError::TargetExists(target.to_path_buf()));
    }

    let lock_path = companion_path(target, ".canonical.lock")?;
    let lock_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CanonicalOutputError::ConcurrentWriter(lock_path));
        }
        Err(source) => return Err(io_error("create canonical output lock", &lock_path, source)),
    };
    let mut lock_cleanup = CleanupFile::new(lock_path);

    if target.exists() {
        return Err(CanonicalOutputError::TargetExists(target.to_path_buf()));
    }

    let (temp_file, mut temp_cleanup) = create_unique_temp(target, hooks)?;
    let mut writer = BufWriter::new(temp_file);
    for value in values {
        serde_json::to_writer(&mut writer, value)
            .map_err(|source| serialization_or_write_error(&temp_cleanup.path, source))?;
        writer.write_all(b"\n").map_err(|source| {
            io_error(
                "write temporary canonical output",
                &temp_cleanup.path,
                source,
            )
        })?;
        hooks
            .checkpoint(
                OutputCheckpoint::AfterJsonWrite,
                target,
                Some(&temp_cleanup.path),
            )
            .map_err(|source| {
                io_error(
                    "write temporary canonical output",
                    &temp_cleanup.path,
                    source,
                )
            })?;
    }
    hooks.flush_temp(&mut writer).map_err(|source| {
        io_error(
            "flush temporary canonical output",
            &temp_cleanup.path,
            source,
        )
    })?;
    let temp_file = writer.into_inner().map_err(|error| {
        io_error(
            "flush temporary canonical output",
            &temp_cleanup.path,
            error.into_error(),
        )
    })?;
    hooks.sync_temp(&temp_file).map_err(|source| {
        io_error(
            "sync temporary canonical output",
            &temp_cleanup.path,
            source,
        )
    })?;
    drop(temp_file);

    hooks
        .checkpoint(
            OutputCheckpoint::BeforePublish,
            target,
            Some(&temp_cleanup.path),
        )
        .map_err(|source| io_error("publish canonical output", target, source))?;

    // `hard_link` is the publication primitive, not an existence check plus an
    // overwrite-capable rename. The temporary file is in the target directory,
    // so this atomically creates the final name on the same filesystem and the
    // operation fails if that name exists at the exact publication point.
    match hooks.publish(&temp_cleanup.path, target) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CanonicalOutputError::TargetExists(target.to_path_buf()));
        }
        Err(source) => return Err(io_error("publish canonical output", target, source)),
    }

    hooks
        .remove_published_temp(&temp_cleanup.path)
        .map_err(|source| {
            published_cleanup_error(
                "remove published temporary link",
                target,
                &temp_cleanup.path,
                source,
            )
        })?;
    temp_cleanup.disarm();

    let directory_sync = hooks.sync_parent(parent);
    drop(lock_file);
    hooks.remove_lock(&lock_cleanup.path).map_err(|source| {
        published_cleanup_error(
            "remove canonical writer lock",
            target,
            &lock_cleanup.path,
            source,
        )
    })?;
    lock_cleanup.disarm();
    directory_sync
        .map_err(|source| published_error("sync canonical output directory", target, source))?;

    Ok(())
}

pub(crate) fn write_jsonl_atomically<T: Serialize>(
    target: impl AsRef<Path>,
    values: &[T],
) -> Result<(), CanonicalOutputError> {
    write_jsonl_atomically_with_hooks(target.as_ref(), values, &NoopOutputHooks)
}

pub fn write_canonical_observations_jsonl(
    target: impl AsRef<Path>,
    observations: &[CanonicalObservation],
) -> Result<(), CanonicalOutputError> {
    write_jsonl_atomically(target, observations)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{self, BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::ser::{Error as _, Serializer};
    use serde::Serialize;

    use super::{
        open_new_temp, sync_parent_directory, write_jsonl_atomically,
        write_jsonl_atomically_with_hooks, CanonicalOutputError, OutputCheckpoint, OutputHooks,
    };

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sih-m1d-output-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn assert_no_companion_artifacts(dir: &Path) {
        let names = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".canonical.lock") || name.ends_with(".tmp"))
            .collect::<Vec<_>>();
        assert!(
            names.is_empty(),
            "unexpected companion artifacts: {names:?}"
        );
    }

    #[derive(Debug)]
    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("injected serialization failure"))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InjectedOperation {
        TempCreate,
        AfterJsonWrite,
        Flush,
        TempSync,
        Publish,
        TempUnlink,
        LockRemove,
        DirectorySync,
    }

    struct FailOperation {
        operation: InjectedOperation,
        observed_nonempty_temp: AtomicBool,
    }

    impl FailOperation {
        fn new(operation: InjectedOperation) -> Self {
            Self {
                operation,
                observed_nonempty_temp: AtomicBool::new(false),
            }
        }

        fn injected(&self, operation: InjectedOperation) -> io::Result<()> {
            if self.operation == operation {
                Err(io::Error::other(format!("injected {operation:?} failure")))
            } else {
                Ok(())
            }
        }
    }

    impl OutputHooks for FailOperation {
        fn create_temp(&self, path: &Path) -> io::Result<fs::File> {
            self.injected(InjectedOperation::TempCreate)?;
            open_new_temp(path)
        }

        fn checkpoint(
            &self,
            checkpoint: OutputCheckpoint,
            _target: &Path,
            temp: Option<&Path>,
        ) -> io::Result<()> {
            if checkpoint == OutputCheckpoint::AfterJsonWrite
                && self.operation == InjectedOperation::AfterJsonWrite
            {
                let nonempty = temp
                    .and_then(|path| fs::metadata(path).ok())
                    .is_some_and(|metadata| metadata.len() > 0);
                self.observed_nonempty_temp
                    .store(nonempty, Ordering::SeqCst);
                self.injected(InjectedOperation::AfterJsonWrite)?;
            }
            Ok(())
        }

        fn flush_temp(&self, writer: &mut BufWriter<fs::File>) -> io::Result<()> {
            self.injected(InjectedOperation::Flush)?;
            writer.flush()
        }

        fn sync_temp(&self, file: &fs::File) -> io::Result<()> {
            self.injected(InjectedOperation::TempSync)?;
            file.sync_all()
        }

        fn publish(&self, temp: &Path, target: &Path) -> io::Result<()> {
            self.injected(InjectedOperation::Publish)?;
            fs::hard_link(temp, target)
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            self.injected(InjectedOperation::DirectorySync)?;
            sync_parent_directory(parent)
        }

        fn remove_published_temp(&self, path: &Path) -> io::Result<()> {
            self.injected(InjectedOperation::TempUnlink)?;
            fs::remove_file(path)
        }

        fn remove_lock(&self, path: &Path) -> io::Result<()> {
            self.injected(InjectedOperation::LockRemove)?;
            fs::remove_file(path)
        }
    }

    struct CreateTargetBeforePublish;

    impl OutputHooks for CreateTargetBeforePublish {
        fn checkpoint(
            &self,
            checkpoint: OutputCheckpoint,
            target: &Path,
            _temp: Option<&Path>,
        ) -> io::Result<()> {
            if checkpoint == OutputCheckpoint::BeforePublish {
                fs::write(target, b"newly created evidence")?;
            }
            Ok(())
        }
    }

    #[test]
    fn empty_and_nonempty_outputs_are_published_with_lf() {
        let dir = test_dir("success");
        let empty = dir.join("empty.jsonl");
        write_jsonl_atomically::<u8>(&empty, &[]).unwrap();
        assert_eq!(fs::read(&empty).unwrap(), b"");

        let populated = dir.join("values.jsonl");
        write_jsonl_atomically(&populated, &[1_u8, 2_u8]).unwrap();
        assert_eq!(fs::read(&populated).unwrap(), b"1\n2\n");

        let unicode = dir.join("unicode.jsonl");
        write_jsonl_atomically(&unicode, &["東京", "évidence"]).unwrap();
        assert_eq!(
            fs::read(&unicode).unwrap(),
            "\"東京\"\n\"évidence\"\n".as_bytes()
        );
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_target_is_never_changed() {
        let dir = test_dir("existing");
        let target = dir.join("canonical.jsonl");
        fs::write(&target, b"existing evidence").unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::TargetExists(_)));
        assert_eq!(fs::read(&target).unwrap(), b"existing evidence");
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn target_appearing_at_publication_is_never_replaced() {
        let dir = test_dir("target-race");
        let target = dir.join("canonical.jsonl");
        let error =
            write_jsonl_atomically_with_hooks(&target, &[1_u8, 2_u8], &CreateTargetBeforePublish)
                .unwrap_err();
        assert!(matches!(error, CanonicalOutputError::TargetExists(_)));
        assert_eq!(fs::read(&target).unwrap(), b"newly created evidence");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn two_real_writers_have_exactly_one_complete_winner() {
        let root = test_dir("concurrent");
        for iteration in 0..64 {
            let dir = root.join(iteration.to_string());
            fs::create_dir(&dir).unwrap();
            let target = Arc::new(dir.join("canonical.jsonl"));
            let barrier = Arc::new(Barrier::new(3));
            let mut handles = Vec::new();
            for values in [vec![111_u16], vec![222_u16, 223_u16]] {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    barrier.wait();
                    write_jsonl_atomically(target.as_ref(), &values)
                }));
            }
            barrier.wait();
            let results = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
            assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
            assert!(results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| matches!(
                    error,
                    CanonicalOutputError::ConcurrentWriter(_)
                        | CanonicalOutputError::TargetExists(_)
                )));
            let final_bytes = fs::read(target.as_ref()).unwrap();
            assert!(final_bytes == b"111\n" || final_bytes == b"222\n223\n");
            assert_no_companion_artifacts(&dir);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_prepublication_failures_clean_temp_lock_and_final() {
        let dir = test_dir("failure-injection");
        for operation in [
            InjectedOperation::TempCreate,
            InjectedOperation::AfterJsonWrite,
            InjectedOperation::Flush,
            InjectedOperation::TempSync,
            InjectedOperation::Publish,
        ] {
            let target = dir.join(format!("{operation:?}.jsonl"));
            let hook = FailOperation::new(operation);
            let error = if operation == InjectedOperation::AfterJsonWrite {
                let value = "x".repeat(16 * 1024);
                write_jsonl_atomically_with_hooks(&target, &[value], &hook).unwrap_err()
            } else {
                write_jsonl_atomically_with_hooks(&target, &[1_u8, 2_u8], &hook).unwrap_err()
            };
            assert!(matches!(error, CanonicalOutputError::Io { .. }));
            assert!(error.to_string().contains("injected"));
            if operation == InjectedOperation::AfterJsonWrite {
                assert!(hook.observed_nonempty_temp.load(Ordering::SeqCst));
            }
            assert!(!target.exists());
            assert_no_companion_artifacts(&dir);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directory_sync_failure_reports_complete_published_artifact() {
        let dir = test_dir("directory-sync");
        let target = dir.join("canonical.jsonl");
        let hook = FailOperation::new(InjectedOperation::DirectorySync);
        let error = write_jsonl_atomically_with_hooks(&target, &[7_u8, 8_u8], &hook).unwrap_err();
        assert!(matches!(
            error,
            CanonicalOutputError::PublishedButDurabilityUnconfirmed { .. }
        ));
        assert!(error.to_string().contains("published completely"));
        assert_eq!(fs::read(&target).unwrap(), b"7\n8\n");
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn postpublication_cleanup_failures_report_complete_final_and_companion_state() {
        let dir = test_dir("postpublication-cleanup");
        for operation in [InjectedOperation::TempUnlink, InjectedOperation::LockRemove] {
            let target = dir.join(format!("{operation:?}.jsonl"));
            let hook = FailOperation::new(operation);
            let error =
                write_jsonl_atomically_with_hooks(&target, &[9_u8, 10_u8], &hook).unwrap_err();
            assert!(matches!(
                error,
                CanonicalOutputError::PublishedButCleanupIncomplete { .. }
            ));
            assert!(error.to_string().contains("published completely"));
            assert!(error.to_string().contains("manual companion cleanup"));
            assert_eq!(fs::read(&target).unwrap(), b"9\n10\n");
            assert_no_companion_artifacts(&dir);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn serialization_failure_leaves_no_final_or_temporary_artifact() {
        let dir = test_dir("serialization");
        let target = dir.join("canonical.jsonl");
        let error = write_jsonl_atomically(&target, &[SerializationFailure]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::Serialization(_)));
        assert!(!target.exists());
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stale_lock_fails_closed_until_operator_removes_it() {
        let dir = test_dir("stale-lock");
        let target = dir.join("canonical.jsonl");
        let lock = dir.join(".canonical.jsonl.canonical.lock");
        fs::write(&lock, b"operator-owned lock evidence").unwrap();

        fs::write(&target, b"existing final evidence").unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::TargetExists(_)));
        assert_eq!(fs::read(&target).unwrap(), b"existing final evidence");
        assert_eq!(fs::read(&lock).unwrap(), b"operator-owned lock evidence");
        fs::remove_file(&target).unwrap();

        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::ConcurrentWriter(_)));
        assert!(!target.exists());
        assert_eq!(fs::read(&lock).unwrap(), b"operator-owned lock evidence");

        fs::remove_file(&lock).unwrap();
        write_jsonl_atomically(&target, &[1_u8]).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"1\n");
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn open_lock_handle_is_never_removed_by_a_competing_writer() {
        let dir = test_dir("open-lock");
        let target = dir.join("canonical.jsonl");
        let lock = dir.join(".canonical.jsonl.canonical.lock");
        let held_lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::ConcurrentWriter(_)));
        assert!(lock.exists());
        assert!(!target.exists());
        drop(held_lock);
        fs::remove_file(&lock).unwrap();
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_parent_and_concurrent_reservation_fail_without_final_artifact() {
        let dir = test_dir("validation");
        let missing_target = dir.join("missing-parent").join("canonical.jsonl");
        let error = write_jsonl_atomically(&missing_target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::ParentUnavailable(_)));
        assert!(!missing_target.exists());

        let target = dir.join("canonical.jsonl");
        let lock = dir.join(".canonical.jsonl.canonical.lock");
        fs::write(&lock, b"reserved").unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::ConcurrentWriter(_)));
        assert!(!target.exists());
        assert_eq!(fs::read(&lock).unwrap(), b"reserved");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directory_target_fails_without_removing_it() {
        let dir = test_dir("directory-target");
        let target = dir.join("canonical.jsonl");
        fs::create_dir(&target).unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::TargetExists(_)));
        assert!(target.is_dir());
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_parent_fails_before_temp_or_final_creation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("unwritable-parent");
        let target = dir.join("canonical.jsonl");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let error = write_jsonl_atomically(&target, &[1_u8]).unwrap_err();
        assert!(matches!(error, CanonicalOutputError::Io { .. }));
        assert!(error.to_string().contains("canonical output lock"));
        assert!(!target.exists());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_no_companion_artifacts(&dir);
        fs::remove_dir_all(dir).unwrap();
    }
}
