use std::sync::Arc;

use crate::mms;

use super::{Client, FileEntry, Result};

/// Streams a server file through successive MMS `fileRead` requests.
///
/// The file-read state machine on the server is released by
/// [`close`](FileReader::close), or when the reader is dropped.
#[derive(Debug)]
pub struct FileReader {
    conn: Arc<mms::Conn>,
    frsm: i32,
    buf: Vec<u8>,
    /// Offset into `buf` of the first unread byte.
    pos: usize,
    /// The server has sent its last chunk.
    done: bool,
    closed: bool,
    /// The size the server reported at open time.
    size: u32,
}

impl Client {
    /// Lists the files under `path`, empty for the filestore root.
    pub async fn file_directory(&self, path: &str) -> Result<Vec<FileEntry>> {
        Ok(self.mms().file_directory(path).await?)
    }

    /// Opens a server file for reading.
    pub async fn open_file(&self, name: &str) -> Result<FileReader> {
        let (frsm, size) = self.mms().file_open(name).await?;
        Ok(FileReader {
            conn: Arc::clone(self.mms()),
            frsm,
            buf: Vec::new(),
            pos: 0,
            done: false,
            closed: false,
            size,
        })
    }

    /// Reads an entire server file into memory.
    pub async fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        let mut r = self.open_file(name).await?;
        let out = r.read_to_end().await;
        // Release the state machine whether or not the read succeeded: a
        // server has a small, fixed number of them.
        let closed = r.close().await;
        let out = out?;
        closed?;
        Ok(out)
    }

    /// Deletes a file from the server's filestore (IEC 61850 DeleteFile).
    pub async fn delete_file(&self, name: &str) -> Result<()> {
        self.mms().file_delete(name).await?;
        Ok(())
    }

    /// Stores `data` in the server's file store as `name` (IEC 61850 SetFile,
    /// which IEC 61850-8-1 maps to MMS obtainFile: the server reads the file
    /// back from this client). The server refuses a name that exists.
    pub async fn set_file(&self, name: &str, data: Vec<u8>) -> Result<()> {
        self.mms()
            .obtain_file(crate::mms::ObtainSource::Bytes(data), SET_FILE_LOCAL_NAME, name)
            .await?;
        Ok(())
    }

    /// [`set_file`](Client::set_file) with the content read from the local
    /// file `src`.
    pub async fn set_file_from(&self, src: impl AsRef<std::path::Path>, name: &str) -> Result<()> {
        let src = src.as_ref();
        let local = src
            .file_name()
            .map_or_else(|| SET_FILE_LOCAL_NAME.to_string(), |n| n.to_string_lossy().into_owned());
        self.mms()
            .obtain_file(crate::mms::ObtainSource::File(src.to_path_buf()), &local, name)
            .await?;
        Ok(())
    }

    /// Renames a file in the server's file store (MMS fileRename). A server
    /// refuses it when the new name is taken.
    pub async fn rename_file(&self, current: &str, renamed: &str) -> Result<()> {
        self.mms().file_rename(current, renamed).await?;
        Ok(())
    }
}

/// The name an in-memory SetFile is served under while the server reads it.
const SET_FILE_LOCAL_NAME: &str = "setfile.bin";

impl FileReader {
    /// Returns the file size the server reported when the file was opened.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Reads the next chunk, or `None` at end of file.
    ///
    /// Chunks are whatever size the server chooses, bounded by the negotiated
    /// PDU size.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // Drain anything left from a partial `read` first.
        if self.pos < self.buf.len() {
            let out = self.buf.split_off(self.pos);
            self.buf.clear();
            self.pos = 0;
            return Ok(Some(out));
        }
        if self.done {
            return Ok(None);
        }
        let (data, more) = self.conn.file_read(self.frsm).await?;
        if !more {
            self.done = true;
        }
        if data.is_empty() && self.done {
            return Ok(None);
        }
        Ok(Some(data))
    }

    /// Fills `out` with up to its length in bytes, returning how many were
    /// read. A return of zero means end of file.
    pub async fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        while self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            let (data, more) = self.conn.file_read(self.frsm).await?;
            if !more {
                self.done = true;
            }
            if data.is_empty() && self.done {
                return Ok(0);
            }
            self.buf = data;
            self.pos = 0;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    /// Reads the rest of the file into memory.
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.size as usize);
        if self.pos < self.buf.len() {
            out.extend_from_slice(&self.buf[self.pos..]);
            self.buf.clear();
            self.pos = 0;
        }
        while !self.done {
            let (data, more) = self.conn.file_read(self.frsm).await?;
            out.extend_from_slice(&data);
            if !more {
                self.done = true;
            }
        }
        Ok(out)
    }

    /// Releases the server's file-read state machine. Calling it twice is
    /// harmless.
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.conn.file_close(self.frsm).await?;
        Ok(())
    }
}

impl Drop for FileReader {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // A server keeps a small, fixed number of file-read state machines, so
        // leaking one costs a later open. Closing needs a round trip, which a
        // Drop cannot await, so it is handed to the runtime.
        let conn = Arc::clone(&self.conn);
        let frsm = self.frsm;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = conn.file_close(frsm).await;
            });
        }
    }
}
