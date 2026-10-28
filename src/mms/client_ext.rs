//! The MMS services beyond the core read/write/browse set: Status,
//! FileRename, ObtainFile (with the file reads this end serves while one is
//! in progress), and the journal status and initialisation services.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::asn1::{
    self, bit_string_elem, bool_elem, cons, context_constructed, context_primitive, int_elem,
    prim, uint_elem, BitString, Decoder, Element, Tag, TAG_GRAPHIC_STRING, TAG_INTEGER,
    TAG_VISIBLE_STRING,
};
use crate::time_util;

use super::conn::Shared;
use super::pdu::*;
use super::server_conn::encode_error_pdu;
use super::services::object_name;
use super::{Conn, Error, ErrorClass, Result, ServiceError, Value};

/// VMD logical status values of the Status service (ISO 9506-2).
pub mod logical {
    pub const STATE_CHANGES_ALLOWED: i64 = 0;
    pub const NO_STATE_CHANGES_ALLOWED: i64 = 1;
    pub const LIMITED_SERVICES_PERMITTED: i64 = 2;
    pub const SUPPORT_SERVICES_ALLOWED: i64 = 3;
}

/// VMD physical status values of the Status service (ISO 9506-2).
pub mod physical {
    pub const OPERATIONAL: i64 = 0;
    pub const PARTIALLY_OPERATIONAL: i64 = 1;
    pub const INOPERABLE: i64 = 2;
    pub const NEEDS_COMMISSIONING: i64 = 3;
}

/// The answer of the Status service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerStatus {
    pub logical: i64,
    pub physical: i64,
    /// The server's implementation-specific status bits, `None` when it sent
    /// none.
    pub local_detail: Option<BitString>,
}

/// The answer of ReportJournalStatus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalStatus {
    pub current_entries: u32,
    /// Whether InitializeJournal may delete entries.
    pub deletable: bool,
}

/// Builds the Status response service element.
pub fn encode_status_response(st: &ServerStatus) -> Element {
    let mut e = cons(
        context_constructed(SVC_STATUS),
        [
            int_elem(context_primitive(0), st.logical),
            int_elem(context_primitive(1), st.physical),
        ],
    );
    if let Some(bs) = &st.local_detail {
        e.push(bit_string_elem(context_primitive(2), bs));
    }
    e
}

fn parse_status(content: &[u8]) -> Result<ServerStatus> {
    let mut dec = Decoder::new(content);
    let mut st = ServerStatus {
        logical: asn1::decode_int(dec.expect(context_primitive(0))?).unwrap_or(0),
        physical: asn1::decode_int(dec.expect(context_primitive(1))?).unwrap_or(0),
        local_detail: None,
    };
    if let Some(b) = dec.optional(context_primitive(2))? {
        st.local_detail = asn1::decode_bit_string(b).ok();
    }
    Ok(st)
}

/// Encodes a FileName, `SEQUENCE OF GraphicString`, under `tag`.
pub(crate) fn file_name(tag: Tag, name: &str) -> Element {
    cons(tag, [prim(TAG_GRAPHIC_STRING, name.as_bytes().to_vec())])
}

/// Decodes the content of a FileName, joining its parts.
pub fn parse_file_name(content: &[u8]) -> Result<String> {
    let mut dec = Decoder::new(content);
    let mut name = String::new();
    while dec.more() {
        let (t, v) = dec.read_tlv()?;
        if t != TAG_GRAPHIC_STRING && t != TAG_VISIBLE_STRING {
            return Err(Error::protocol(format!("file name part of tag {t}")));
        }
        name.push_str(&String::from_utf8_lossy(v));
    }
    Ok(name)
}

/// Decodes the content of a FileRename-Request into the current and the new
/// name.
pub fn parse_file_rename(content: &[u8]) -> Result<(String, String)> {
    let mut dec = Decoder::new(content);
    let mut names = Vec::with_capacity(2);
    for i in 0..2 {
        let (t, v) = dec.read_tlv()?;
        if t != context_constructed(i) {
            return Err(Error::protocol(format!(
                "FileRename-Request element {i} has tag {t}"
            )));
        }
        names.push(parse_file_name(v)?);
    }
    let renamed = names.pop().unwrap_or_default();
    let current = names.pop().unwrap_or_default();
    Ok((current, renamed))
}

/// The GeneralizedTime encoding of `t` in UTC, `YYYYMMDDHHMMSS.sssZ`.
pub(crate) fn generalized_time(t: SystemTime) -> Vec<u8> {
    let (secs, nanos) = time_util::unix_parts(t);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = time_util::civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        nanos / 1_000_000
    )
    .into_bytes()
}

/// What [`Conn::obtain_file`] serves the server when it reads the file back.
#[derive(Debug, Clone)]
pub enum ObtainSource {
    /// The file's content, held in memory.
    Bytes(Vec<u8>),
    /// A local file whose content is served.
    File(PathBuf),
}

/// The file service error codes of class file (11).
mod file_err {
    pub const SYNTAX: u8 = 3;
    pub const POSITION_INVALID: u8 = 5;
    pub const ACCESS_DENIED: u8 = 6;
    pub const NON_EXISTENT: u8 = 7;
}

fn file_error(code: u8) -> Error {
    Error::Service(ServiceError::new(ErrorClass::FILE, code))
}

fn unrecognised() -> Error {
    Error::Service(ServiceError {
        rejected: true,
        ..ServiceError::new(ErrorClass(1), 1)
    })
}

/// The most a fileRead response carries.
const FILE_CHUNK: usize = 8192;

/// An open file of a [`FileServer`]: its content and the read position.
type OpenFile = (Arc<Vec<u8>>, usize);

/// Answers the file reads of an ObtainFile: it serves one name, the source
/// file, and nothing else.
pub(crate) struct FileServer {
    name: String,
    source: ObtainSource,
    next: AtomicI32,
    open: Mutex<HashMap<i32, OpenFile>>,
}

impl FileServer {
    fn handle(&self, service: u32, body: &[u8]) -> Result<Element> {
        match service {
            SVC_FILE_OPEN => {
                let mut dec = Decoder::new(body);
                let nb = dec
                    .expect(context_constructed(0))
                    .map_err(|_| file_error(file_err::SYNTAX))?;
                let name = parse_file_name(nb).map_err(|_| file_error(file_err::ACCESS_DENIED))?;
                if name != self.name {
                    return Err(file_error(file_err::ACCESS_DENIED));
                }
                let pos = match dec.optional(context_primitive(1)) {
                    Ok(Some(pb)) => asn1::decode_uint(pb).unwrap_or(0) as usize,
                    _ => 0,
                };
                let (data, modified) = match &self.source {
                    ObtainSource::Bytes(b) => (b.clone(), SystemTime::now()),
                    ObtainSource::File(p) => {
                        let meta = std::fs::metadata(p).map_err(|_| file_error(file_err::NON_EXISTENT))?;
                        if meta.is_dir() {
                            return Err(file_error(file_err::NON_EXISTENT));
                        }
                        let data = std::fs::read(p).map_err(|_| file_error(file_err::NON_EXISTENT))?;
                        (data, meta.modified().unwrap_or_else(|_| SystemTime::now()))
                    }
                };
                if pos > data.len() {
                    return Err(file_error(file_err::POSITION_INVALID));
                }
                let size = data.len();
                let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
                self.open
                    .lock()
                    .unwrap()
                    .insert(id, (Arc::new(data), pos));
                Ok(cons(
                    context_constructed(SVC_FILE_OPEN),
                    [
                        int_elem(context_primitive(0), i64::from(id)),
                        cons(
                            context_constructed(1),
                            [
                                uint_elem(context_primitive(0), size as u64),
                                prim(context_primitive(1), generalized_time(modified)),
                            ],
                        ),
                    ],
                ))
            }
            SVC_FILE_READ => {
                let id = asn1::decode_int(body).map_err(|_| file_error(file_err::SYNTAX))? as i32;
                let mut open = self.open.lock().unwrap();
                let (data, pos) = open.get_mut(&id).ok_or_else(|| file_error(file_err::NON_EXISTENT))?;
                let end = (*pos + FILE_CHUNK).min(data.len());
                let chunk = data[*pos..end].to_vec();
                *pos = end;
                let more = end < data.len();
                Ok(cons(
                    context_constructed(SVC_FILE_READ),
                    [
                        prim(context_primitive(0), chunk),
                        bool_elem(context_primitive(1), more),
                    ],
                ))
            }
            SVC_FILE_CLOSE => {
                let id = asn1::decode_int(body).map_err(|_| file_error(file_err::SYNTAX))? as i32;
                self.open.lock().unwrap().remove(&id);
                Ok(prim(context_primitive(SVC_FILE_CLOSE), Vec::new()))
            }
            _ => Err(unrecognised()),
        }
    }
}

/// Answers a confirmed request from the server. Only the file reads of an
/// ObtainFile in progress are served; anything else is rejected as
/// unrecognised.
pub(crate) async fn serve_request(shared: &Arc<Shared>, content: &[u8]) {
    let mut dec = Decoder::new(content);
    let Ok(id_bytes) = dec.expect(TAG_INTEGER) else {
        return;
    };
    let id = asn1::decode_uint(id_bytes).unwrap_or(0) as u32;
    let Ok((tag, body)) = dec.read_tlv() else {
        return;
    };
    let files = shared.files.lock().unwrap().clone();
    let res = match files {
        Some(f) => f.handle(tag.number, body),
        None => Err(unrecognised()),
    };
    let out = match res {
        Ok(resp) => cons(
            TAG_CONFIRMED_RESPONSE,
            [asn1::uint_elem(TAG_INTEGER, u64::from(id)), resp],
        )
        .encode(),
        Err(e) => encode_error_pdu(id, &e),
    };
    let _ = shared.writer.lock().await.send_mms(&out).await;
}

impl Conn {
    /// Asks the server for the status of its virtual device (MMS Status).
    ///
    /// `extended` asks it to derive the status afresh rather than report its
    /// last one.
    pub async fn status(&self, extended: bool) -> Result<ServerStatus> {
        let resp = self
            .call_inner(bool_elem(context_primitive(SVC_STATUS), extended))
            .await?;
        let content = Decoder::new(&resp).expect(context_constructed(SVC_STATUS))?;
        parse_status(content)
    }

    /// Renames a file of the server's file store (MMS fileRename).
    ///
    /// IEC 61850 maps no ACSI service to it; a server that implements it
    /// advertises it in its Initiate response.
    pub async fn file_rename(&self, current: &str, renamed: &str) -> Result<()> {
        self.call_inner(cons(
            context_constructed(SVC_FILE_RENAME),
            [
                file_name(context_constructed(0), current),
                file_name(context_constructed(1), renamed),
            ],
        ))
        .await?;
        Ok(())
    }

    /// Has the server fetch `source_file` from this end and store it as
    /// `destination_file` (MMS obtainFile, which IEC 61850-8-1 maps SetFile
    /// to).
    ///
    /// While the request is outstanding the server reads the file from
    /// `source` with fileOpen, fileRead and fileClose requests, which this
    /// connection answers; it serves `source_file` and nothing else. One
    /// ObtainFile runs at a time.
    pub async fn obtain_file(
        &self,
        source: ObtainSource,
        source_file: &str,
        destination_file: &str,
    ) -> Result<()> {
        let _one = self.obtain_lock.lock().await;
        let server = Arc::new(FileServer {
            name: source_file.to_string(),
            source,
            next: AtomicI32::new(0),
            open: Mutex::new(HashMap::new()),
        });
        *self.shared().files.lock().unwrap() = Some(server);
        let req = cons(
            context_constructed(SVC_OBTAIN_FILE),
            [
                file_name(context_constructed(1), source_file),
                file_name(context_constructed(2), destination_file),
            ],
        );
        // The server reads the whole file before it answers, so the request
        // timeout, sized for one exchange, does not apply.
        let res = self.call_unbounded(req).await;
        *self.shared().files.lock().unwrap() = None;
        res.map(|_| ())
    }

    /// Asks for the number of entries of a journal (an IEC 61850 log) and
    /// whether it may be initialised.
    pub async fn report_journal_status(&self, domain: &str, item: &str) -> Result<JournalStatus> {
        let resp = self
            .call_inner(cons(
                context_constructed(SVC_REPORT_JOURNAL_STATUS),
                [object_name(domain, item)],
            ))
            .await?;
        let content = Decoder::new(&resp).expect(context_constructed(SVC_REPORT_JOURNAL_STATUS))?;
        let mut dec = Decoder::new(content);
        let n = asn1::decode_uint(dec.expect(context_primitive(0))?).unwrap_or(0);
        let b = dec.expect(context_primitive(1))?;
        Ok(JournalStatus {
            current_entries: n as u32,
            deletable: b.len() == 1 && b[0] != 0,
        })
    }

    /// Deletes entries of a journal and returns how many it deleted: all of
    /// them when `until` is `None`, else those up to and including the time
    /// `until` and, when `entry_id` is not empty, no further than the entry
    /// it names.
    pub async fn initialize_journal(
        &self,
        domain: &str,
        item: &str,
        until: Option<SystemTime>,
        entry_id: &[u8],
    ) -> Result<u32> {
        let mut req = cons(
            context_constructed(SVC_INITIALIZE_JOURNAL),
            [cons(context_constructed(0), [object_name(domain, item)])],
        );
        if let Some(t) = until {
            let mut limit = cons(
                context_constructed(1),
                [prim(context_primitive(0), Value::binary_time(t).bytes().to_vec())],
            );
            if !entry_id.is_empty() {
                limit.push(prim(context_primitive(1), entry_id.to_vec()));
            }
            req.push(limit);
        }
        let resp = self.call_inner(req).await?;
        let b = Decoder::new(&resp).expect(context_primitive(SVC_INITIALIZE_JOURNAL))?;
        Ok(asn1::decode_uint(b)? as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_response_round_trips() {
        let mut bs = BitString::new(3);
        bs.set_bit(1, true);
        let st = ServerStatus {
            logical: logical::NO_STATE_CHANGES_ALLOWED,
            physical: physical::INOPERABLE,
            local_detail: Some(bs),
        };
        let e = encode_status_response(&st).encode();
        let content = Decoder::new(&e).expect(context_constructed(SVC_STATUS)).unwrap();
        assert_eq!(parse_status(content).unwrap(), st);
    }

    #[test]
    fn a_file_rename_request_parses_back() {
        let req = cons(
            context_constructed(SVC_FILE_RENAME),
            [
                file_name(context_constructed(0), "a/old.txt"),
                file_name(context_constructed(1), "a/new.txt"),
            ],
        )
        .encode();
        let content = Decoder::new(&req)
            .expect(context_constructed(SVC_FILE_RENAME))
            .unwrap();
        assert_eq!(
            parse_file_rename(content).unwrap(),
            ("a/old.txt".to_string(), "a/new.txt".to_string())
        );
    }

    #[test]
    fn the_file_server_serves_its_one_file_in_chunks() {
        let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        let fs = FileServer {
            name: "src.bin".into(),
            source: ObtainSource::Bytes(data.clone()),
            next: AtomicI32::new(0),
            open: Mutex::new(HashMap::new()),
        };
        let open = |name: &str| {
            fs.handle(
                SVC_FILE_OPEN,
                &cons(context_constructed(0), [file_name(context_constructed(0), name)])
                    .encode()[2..],
            )
        };
        assert!(open("other").is_err(), "only the source file is served");
        let resp = open("src.bin").unwrap().encode();
        let content = Decoder::new(&resp).expect(context_constructed(SVC_FILE_OPEN)).unwrap();
        let id = asn1::decode_int(Decoder::new(content).expect(context_primitive(0)).unwrap()).unwrap();
        let mut got = Vec::new();
        loop {
            let r = fs
                .handle(SVC_FILE_READ, &int_elem(TAG_INTEGER, id).encode()[2..])
                .unwrap()
                .encode();
            let c = Decoder::new(&r).expect(context_constructed(SVC_FILE_READ)).unwrap();
            let mut d = Decoder::new(c);
            got.extend_from_slice(d.expect(context_primitive(0)).unwrap());
            let more = asn1::decode_bool(d.expect(context_primitive(1)).unwrap()).unwrap();
            if !more {
                break;
            }
        }
        assert_eq!(got, data);
    }

    #[test]
    fn generalized_time_is_utc() {
        let t = time_util::from_unix(1_700_000_000, 123_000_000);
        assert_eq!(generalized_time(t), b"20231114221320.123Z");
    }
}
