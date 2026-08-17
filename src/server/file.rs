//! Serves the MMS file services from a directory on disk.
//!
//! Open files are tracked by file-read state machine id, and read whole at
//! open time so a later read cannot fail halfway through a transfer.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// Bounds a single `fileRead` response payload.
///
/// It has to stay well inside the negotiated PDU size, which is 65000 octets
/// by default.
pub const FILE_CHUNK_SIZE: usize = 8000;

/// One entry of a filestore directory listing.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u32,
    pub modified: Option<SystemTime>,
}

/// A file the server has open for a client.
#[derive(Debug)]
struct OpenFile {
    data: Vec<u8>,
    pos: usize,
}

/// The server's filestore.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
    state: Mutex<FileStoreState>,
}

#[derive(Debug, Default)]
struct FileStoreState {
    next: i32,
    open: HashMap<i32, OpenFile>,
}

impl FileStore {
    pub fn new(root: impl Into<PathBuf>) -> FileStore {
        FileStore {
            root: root.into(),
            state: Mutex::new(FileStoreState {
                next: 1,
                open: HashMap::new(),
            }),
        }
    }

    /// Resolves a client-supplied name against the filestore root.
    ///
    /// Any component that would escape the root is refused: a client naming
    /// `../../etc/passwd` must not read outside the filestore, and MMS file
    /// names are opaque strings a client chooses freely.
    pub fn resolve(&self, name: &str) -> Option<PathBuf> {
        let requested = Path::new(name.trim_start_matches('/'));
        let mut out = self.root.clone();
        for c in requested.components() {
            match c {
                Component::Normal(part) => out.push(part),
                // "." is harmless; everything else could leave the root.
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        Some(out)
    }

    /// Opens a file for reading, returning its state machine id, size and
    /// modification time.
    ///
    /// Opening a directory is refused as unsupported rather than as
    /// non-existent: a client that walked a listing and picked a directory
    /// entry deserves to be told which of the two it got wrong.
    pub fn open(&self, name: &str) -> std::io::Result<(i32, u32, Option<SystemTime>)> {
        let path = self.resolve(name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file name escapes the filestore",
            )
        })?;
        let meta = std::fs::metadata(&path)?;
        if meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the name addresses a directory, not a file",
            ));
        }
        let data = std::fs::read(&path)?;
        let modified = meta.modified().ok();
        let size = data.len().min(u32::MAX as usize) as u32;

        let mut st = self.state.lock().unwrap();
        let id = st.next;
        st.next = st.next.wrapping_add(1).max(1);
        st.open.insert(id, OpenFile { data, pos: 0 });
        Ok((id, size, modified))
    }

    /// Reads the next chunk of an open file.
    ///
    /// Returns the chunk and whether more follows, or `None` when the id names
    /// no open file.
    pub fn read(&self, id: i32) -> Option<(Vec<u8>, bool)> {
        let mut st = self.state.lock().unwrap();
        let f = st.open.get_mut(&id)?;
        let end = (f.pos + FILE_CHUNK_SIZE).min(f.data.len());
        let chunk = f.data[f.pos..end].to_vec();
        f.pos = end;
        let more = f.pos < f.data.len();
        Some((chunk, more))
    }

    /// Releases a file-read state machine.
    pub fn close(&self, id: i32) {
        self.state.lock().unwrap().open.remove(&id);
    }

    /// Lists the entries under `dir`, empty for the filestore root.
    ///
    /// Directories are listed with a trailing separator, which is how MMS
    /// filestores distinguish them.
    pub fn list(&self, dir: &str) -> std::io::Result<Vec<FileInfo>> {
        let path = self.resolve(dir).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "directory name escapes the filestore",
            )
        })?;
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let mut name = entry.file_name().to_string_lossy().into_owned();
            // Prefix with the requested directory so the name a client sees is
            // the one it can open.
            let prefix = dir.trim_matches('/');
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
            if meta.is_dir() {
                name.push('/');
            }
            out.push(FileInfo {
                name,
                size: meta.len().min(u64::from(u32::MAX)) as u32,
                modified: meta.modified().ok(),
            });
        }
        // A stable order, since a client pages through the listing by name.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes a file from the filestore.
    pub fn delete(&self, name: &str) -> std::io::Result<()> {
        let path = self.resolve(name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file name escapes the filestore",
            )
        })?;
        std::fs::remove_file(path)
    }

    /// Returns how many files are open, for diagnostics.
    pub fn open_count(&self) -> usize {
        self.state.lock().unwrap().open.len()
    }
}

/// Formats a time as the ASN.1 GeneralizedTime MMS uses for file timestamps.
pub fn generalized_time(t: SystemTime) -> String {
    let (secs, _) = crate::time_util::unix_parts(t);
    let (y, mo, d, h, mi, s) = crate::time_util::civil_from_unix(secs);
    format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (FileStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rs-iec61850-filestore-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("COMTRADE")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("COMTRADE/rec001.cfg"), vec![b'x'; 20_000]).unwrap();
        (FileStore::new(&dir), dir)
    }

    /// MMS file names are opaque strings the client chooses, so a traversal
    /// attempt has to be refused rather than resolved.
    #[test]
    fn names_that_escape_the_filestore_are_refused() {
        let store = FileStore::new("/var/comtrade");
        assert!(store.resolve("../../etc/passwd").is_none());
        assert!(store.resolve("COMTRADE/../../etc/passwd").is_none());
        assert!(store.resolve("/etc/passwd").is_some(), "a leading slash is stripped");
        assert_eq!(
            store.resolve("/etc/passwd").unwrap(),
            Path::new("/var/comtrade/etc/passwd"),
            "and resolved inside the root"
        );

        // Ordinary names resolve below the root.
        assert_eq!(
            store.resolve("COMTRADE/rec001.cfg").unwrap(),
            Path::new("/var/comtrade/COMTRADE/rec001.cfg")
        );
        assert_eq!(
            store.resolve("./a.txt").unwrap(),
            Path::new("/var/comtrade/a.txt")
        );
    }

    #[test]
    fn opening_a_file_reports_its_size_and_reads_it_in_chunks() {
        let (store, dir) = temp_store();
        let (id, size, modified) = store.open("COMTRADE/rec001.cfg").unwrap();
        assert_eq!(size, 20_000);
        assert!(modified.is_some());
        assert_eq!(store.open_count(), 1);

        let mut total = 0;
        let mut chunks = 0;
        loop {
            let (chunk, more) = store.read(id).unwrap();
            total += chunk.len();
            chunks += 1;
            if !more {
                break;
            }
            assert_eq!(chunk.len(), FILE_CHUNK_SIZE);
        }
        assert_eq!(total, 20_000);
        assert_eq!(chunks, 3, "20000 bytes in 8000-byte chunks");

        store.close(id);
        assert_eq!(store.open_count(), 0);
        assert!(store.read(id).is_none(), "a closed id reads nothing");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_small_file_is_one_chunk_with_no_more_following() {
        let (store, dir) = temp_store();
        let (id, size, _) = store.open("a.txt").unwrap();
        assert_eq!(size, 5);
        let (chunk, more) = store.read(id).unwrap();
        assert_eq!(chunk, b"hello");
        assert!(!more);
        store.close(id);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_file_fails_to_open() {
        let (store, dir) = temp_store();
        assert!(store.open("nope.txt").is_err());
        assert!(store.open("../escape").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A client that walks a listing and picks a directory entry gets a
    /// specific complaint, not "no such file", which would send it looking for
    /// a name it had just been given.
    #[test]
    fn opening_a_directory_is_refused_as_invalid_rather_than_missing() {
        let (store, dir) = temp_store();
        let err = store.open("COMTRADE").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            store.open("nope.txt").unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "a genuinely missing file is still NotFound"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn listing_returns_names_a_client_can_open() {
        let (store, dir) = temp_store();
        let root = store.list("").unwrap();
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(
            names.contains(&"COMTRADE/"),
            "directories carry a trailing separator: {names:?}"
        );

        let sub = store.list("COMTRADE").unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(
            sub[0].name, "COMTRADE/rec001.cfg",
            "the name must be openable as reported"
        );
        assert_eq!(sub[0].size, 20_000);
        // And it is: opening the reported name works.
        assert!(store.open(&sub[0].name).is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn generalized_times_are_the_form_mms_expects() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_786_838_400);
        assert_eq!(generalized_time(t), "20260816000000Z");
        assert_eq!(generalized_time(std::time::UNIX_EPOCH), "19700101000000Z");
    }

    #[test]
    fn several_files_open_at_once_read_independently() {
        let (store, dir) = temp_store();
        let (a, _, _) = store.open("a.txt").unwrap();
        let (b, _, _) = store.open("COMTRADE/rec001.cfg").unwrap();
        assert_ne!(a, b, "each open gets its own state machine");

        let (chunk_a, _) = store.read(a).unwrap();
        assert_eq!(chunk_a, b"hello");
        let (chunk_b, more_b) = store.read(b).unwrap();
        assert_eq!(chunk_b.len(), FILE_CHUNK_SIZE);
        assert!(more_b, "the other file's read did not disturb this one");

        store.close(a);
        assert!(store.read(b).is_some(), "closing one leaves the other open");

        let _ = std::fs::remove_dir_all(dir);
    }
}
