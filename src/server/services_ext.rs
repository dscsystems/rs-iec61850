//! The MMS services beyond reading, writing and browsing: Status, the journal
//! services, and the file services that change the file store (FileDelete,
//! FileRename, and SetFile through ObtainFile).

use std::io::Write as _;
use std::time::Duration;

use crate::asn1::{
    self, bool_elem, cons, context_constructed, context_primitive, prim, uint_elem, Decoder,
    Element,
};
use crate::mms::{self, DataAccessError, ErrorClass, ServiceError, Value};

use super::handler::{
    Handler, SVC_FILE_CLOSE, SVC_FILE_DELETE, SVC_FILE_OPEN, SVC_FILE_READ, SVC_FILE_RENAME,
    SVC_INITIALIZE_JOURNAL, SVC_OBTAIN_FILE, SVC_REPORT_JOURNAL_STATUS,
};
use super::journal;

/// MMS file error codes (class file, 11).
mod file_err {
    pub const NAME_SYNTAX: u8 = 3;
    pub const ACCESS_DENIED: u8 = 6;
    pub const NON_EXISTENT: u8 = 7;
    pub const DUPLICATE_NAME: u8 = 8;
    pub const INSUFFICIENT_SPACE: u8 = 9;
}

fn file_error(code: u8) -> mms::Error {
    mms::Error::Service(ServiceError::new(ErrorClass::FILE, code))
}

/// Bounds a file SetFile may write.
const MAX_OBTAINED_FILE: usize = 256 << 20;

/// Bounds how long the server waits for the client during an ObtainFile.
const OBTAIN_TIMEOUT: Duration = Duration::from_secs(120);

impl Handler {
    pub(crate) fn server_status(&self) -> Element {
        let (logical, physical) = self.inner.status();
        mms::encode_status_response(&mms::ServerStatus {
            logical,
            physical,
            local_detail: None,
        })
    }

    /// Answers ReadJournal with as many of the selected entries as fit the
    /// association's maximum PDU, and moreFollows when the client has to
    /// continue after the last one.
    pub(crate) fn read_journal(&self, content: &[u8], max_pdu: usize) -> mms::Result<Element> {
        let q = journal::parse_journal_query(content)?;
        let _model = self.inner.model.read().unwrap();
        self.inner
            .logs
            .with_journal(&q.domain, &q.name, |j| {
                journal::read_journal_response(&q, j, max_pdu)
            })
            .ok_or_else(|| DataAccessError::ObjectNonExistent.into())
    }

    pub(crate) fn report_journal_status(&self, content: &[u8]) -> mms::Result<Element> {
        let (domain, item) = super::handler::parse_object_name(content)?;
        let _model = self.inner.model.read().unwrap();
        let n = self
            .inner
            .logs
            .with_journal(&domain, &item, |j| j.entries.len())
            .ok_or(DataAccessError::ObjectNonExistent)?;
        Ok(cons(
            context_constructed(SVC_REPORT_JOURNAL_STATUS),
            [
                uint_elem(context_primitive(0), n as u64),
                bool_elem(context_primitive(1), self.inner.deletable_logs),
            ],
        ))
    }

    /// Deletes log entries: all of them, or those up to the limiting time,
    /// stopping at the limiting entry when one is named.
    pub(crate) fn initialize_journal(&self, content: &[u8]) -> mms::Result<Element> {
        let mut dec = Decoder::new(content);
        let name = dec.expect(context_constructed(0))?;
        let (domain, item) = super::handler::parse_object_name(name)?;
        let mut limit = None;
        let mut limit_entry = None;
        if let Some(ls) = dec.optional(context_constructed(1))? {
            let mut ld = Decoder::new(ls);
            let tb = ld.expect(context_primitive(0))?;
            limit = Value::binary_time_raw(tb)?.time();
            limit_entry = ld.optional(context_primitive(1))?.map(<[u8]>::to_vec);
        }
        let mut model = self.inner.model.write().unwrap();
        let deletable = self.inner.deletable_logs;
        let n = self
            .inner
            .logs
            .with_journal(&domain, &item, |j| {
                if !deletable {
                    return None;
                }
                let mut n = j.entries.len();
                if let Some(limit) = limit {
                    n = 0;
                    for e in &j.entries {
                        if e.time > limit {
                            break;
                        }
                        n += 1;
                        if limit_entry.as_deref() == Some(e.id.as_slice()) {
                            break;
                        }
                    }
                }
                j.entries.drain(..n);
                Some(n)
            })
            .ok_or(DataAccessError::ObjectNonExistent)?
            .ok_or(DataAccessError::ObjectAccessDenied)?;
        self.inner.logs.sync_journal(&mut model, &domain, &item);
        tracing::info!(log = %item, deleted = n, "server: log entries deleted");
        Ok(uint_elem(context_primitive(SVC_INITIALIZE_JOURNAL), n as u64))
    }

    fn writable_store(&self) -> mms::Result<&super::FileStore> {
        match &self.inner.files {
            Some(f) if f.is_writable() => Ok(f),
            _ => Err(file_error(file_err::ACCESS_DENIED)),
        }
    }

    pub(crate) fn file_delete(&self, content: &[u8]) -> mms::Result<Element> {
        let files = self.writable_store()?;
        // Earlier versions of this crate's client wrapped the name in [0].
        let content = Decoder::new(content)
            .optional(context_constructed(0))
            .ok()
            .flatten()
            .unwrap_or(content);
        let name = mms::parse_file_name(content).map_err(|_| file_error(file_err::NAME_SYNTAX))?;
        files.delete(&name).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => file_error(file_err::NON_EXISTENT),
            std::io::ErrorKind::InvalidInput => file_error(file_err::NAME_SYNTAX),
            _ => file_error(file_err::ACCESS_DENIED),
        })?;
        tracing::info!(file = %name, "server: file deleted");
        Ok(prim(context_primitive(SVC_FILE_DELETE), Vec::new()))
    }

    pub(crate) fn file_rename(&self, content: &[u8]) -> mms::Result<Element> {
        let files = self.writable_store()?;
        let (old, new) =
            mms::parse_file_rename(content).map_err(|_| file_error(file_err::NAME_SYNTAX))?;
        files.rename(&old, &new).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => file_error(file_err::NON_EXISTENT),
            std::io::ErrorKind::AlreadyExists => file_error(file_err::DUPLICATE_NAME),
            std::io::ErrorKind::InvalidInput => file_error(file_err::NAME_SYNTAX),
            _ => file_error(file_err::ACCESS_DENIED),
        })?;
        tracing::info!(from = %old, to = %new, "server: file renamed");
        Ok(prim(context_primitive(SVC_FILE_RENAME), Vec::new()))
    }

    /// Serves ObtainFile (IEC 61850 SetFile): the server reads `sourceFile`
    /// from the client with fileOpen, fileRead and fileClose, and stores it as
    /// `destinationFile`. The reads go through the connection while it keeps
    /// serving, so the request is deferred.
    pub(crate) async fn obtain_file(&self, content: &[u8], conn: &mms::ServerConn) -> mms::Result<Element> {
        let files = self.writable_store()?;
        let mut dec = Decoder::new(content);
        if dec.optional(context_constructed(0))?.is_some() {
            // A third-party source file server: this server can only read from
            // the client that asked. application-reference: invalid.
            return Err(mms::Error::Service(ServiceError::new(ErrorClass::APPLICATION_REFERENCE, 3)));
        }
        let src = dec
            .expect(context_constructed(1))
            .ok()
            .and_then(|c| mms::parse_file_name(c).ok())
            .ok_or_else(|| file_error(file_err::NAME_SYNTAX))?;
        let dst = dec
            .expect(context_constructed(2))
            .ok()
            .and_then(|c| mms::parse_file_name(c).ok())
            .ok_or_else(|| file_error(file_err::NAME_SYNTAX))?;
        if files.resolve(&dst).is_none() {
            return Err(file_error(file_err::NAME_SYNTAX));
        }
        if files.exists(&dst) {
            return Err(file_error(file_err::DUPLICATE_NAME));
        }
        let res = tokio::time::timeout(OBTAIN_TIMEOUT, fetch_file(conn, files, &src, &dst)).await;
        let res = res.unwrap_or_else(|_| Err(file_error(file_err::ACCESS_DENIED)));
        if let Err(e) = res {
            let _ = files.delete(&dst);
            tracing::warn!(source = %src, file = %dst, error = %e, "server: SetFile failed");
            return Err(match e {
                mms::Error::Service(se) => mms::Error::Service(se),
                _ => file_error(file_err::ACCESS_DENIED),
            });
        }
        tracing::info!(file = %dst, "server: file written");
        Ok(prim(context_primitive(SVC_OBTAIN_FILE), Vec::new()))
    }
}

/// Reads `src` from the client into a new file `dst`.
async fn fetch_file(
    conn: &mms::ServerConn,
    files: &super::FileStore,
    src: &str,
    dst: &str,
) -> mms::Result<()> {
    let resp = conn
        .call(cons(
            context_constructed(SVC_FILE_OPEN),
            [
                cons(
                    context_constructed(0),
                    [prim(asn1::TAG_GRAPHIC_STRING, src.as_bytes().to_vec())],
                ),
                uint_elem(context_primitive(1), 0),
            ],
        ))
        .await?;
    let content = Decoder::new(&resp).expect(context_constructed(SVC_FILE_OPEN))?;
    let frsm = asn1::decode_int(Decoder::new(content).expect(context_primitive(0))?)?;
    let res = copy_file(conn, files, dst, frsm).await;
    let _ = conn
        .call(asn1::int_elem(context_primitive(SVC_FILE_CLOSE), frsm))
        .await;
    res
}

async fn copy_file(
    conn: &mms::ServerConn,
    files: &super::FileStore,
    dst: &str,
    frsm: i64,
) -> mms::Result<()> {
    let mut out = files.create_new(dst).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => file_error(file_err::DUPLICATE_NAME),
        _ => file_error(file_err::ACCESS_DENIED),
    })?;
    let mut written = 0usize;
    loop {
        let resp = conn
            .call(asn1::int_elem(context_primitive(SVC_FILE_READ), frsm))
            .await?;
        let rc = Decoder::new(&resp).expect(context_constructed(SVC_FILE_READ))?;
        let mut rd = Decoder::new(rc);
        let data = rd.expect(context_primitive(0))?;
        // moreFollows DEFAULT TRUE
        let more = match rd.optional(context_primitive(1))? {
            Some(b) => b.len() == 1 && b[0] != 0,
            None => true,
        };
        written += data.len();
        if written > MAX_OBTAINED_FILE {
            return Err(file_error(file_err::INSUFFICIENT_SPACE));
        }
        out.write_all(data)
            .map_err(|_| file_error(file_err::INSUFFICIENT_SPACE))?;
        if !more {
            break;
        }
    }
    out.flush().map_err(|_| file_error(file_err::INSUFFICIENT_SPACE))?;
    Ok(())
}
