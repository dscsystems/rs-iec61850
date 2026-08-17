use std::time::SystemTime;

use crate::asn1::{
    self, bool_elem, cons, context_constructed, context_primitive, int_elem, prim, uint_elem,
    Decoder, Element, TAG_GRAPHIC_STRING, TAG_SEQUENCE, TAG_VISIBLE_STRING,
};
use crate::time_util;

use super::pdu::*;
use super::{
    decode_access_result, decode_type_spec, Conn, DataAccessError, Error, Result, TypeSpec, Value,
};

/// Identifies the object class for `getNameList`.
///
/// Servers commonly implement only a subset; `getNameList` for an unsupported
/// class answers with an access error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ObjectClass {
    NamedVariable = 0,
    ScatteredAccess = 1,
    NamedVariableList = 2,
    NamedType = 3,
    Semaphore = 4,
    EventCondition = 5,
    EventAction = 6,
    EventEnrollment = 7,
    Journal = 8,
    Domain = 9,
    ProgramInvocation = 10,
    OperatorStation = 11,
}

/// Names a domain variable: a domain plus an MMS itemID.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarRef {
    pub domain: String,
    pub item: String,
}

impl VarRef {
    pub fn new(domain: impl Into<String>, item: impl Into<String>) -> VarRef {
        VarRef {
            domain: domain.into(),
            item: item.into(),
        }
    }

    /// Reports whether the reference names nothing.
    pub fn is_empty(&self) -> bool {
        self.domain.is_empty() && self.item.is_empty()
    }
}

impl std::fmt::Display for VarRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.domain, self.item)
    }
}

/// Describes one entry returned by [`Conn::file_directory`].
#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    pub name: String,
    pub size: u32,
    pub last_modified: Option<SystemTime>,
}

/// One entry returned by a `readJournal` query.
#[derive(Debug, Clone, Default)]
pub struct JournalEntry {
    pub entry_id: Vec<u8>,
    pub occurrence_time: Option<SystemTime>,
    pub variables: Vec<JournalVariable>,
}

/// One logged variable within a journal entry.
#[derive(Debug, Clone)]
pub struct JournalVariable {
    pub tag: String,
    pub value: Option<Value>,
}

/// Builds an MMS ObjectName.
///
/// An empty domain yields the vmd-specific alternative; otherwise it is
/// domain-specific with the given itemID.
pub(crate) fn object_name(domain: &str, item: &str) -> Element {
    if domain.is_empty() {
        return prim(context_primitive(0), item.as_bytes().to_vec()); // vmd-specific
    }
    cons(
        context_constructed(1), // domain-specific
        [
            prim(TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
            prim(TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
        ],
    )
}

/// Builds one `ListOfVariable` entry naming a domain variable.
fn variable_entry(domain: &str, item: &str) -> Element {
    cons(
        TAG_SEQUENCE,
        // variableSpecification: name [0]
        [cons(context_constructed(0), [object_name(domain, item)])],
    )
}

/// Decodes an ObjectName element's content into a [`VarRef`].
pub(crate) fn parse_object_name(content: &[u8]) -> Result<VarRef> {
    let mut dec = Decoder::new(content);
    let (tag, c) = dec.read_tlv()?;
    if tag == context_primitive(0) {
        // vmd-specific
        Ok(VarRef {
            domain: String::new(),
            item: String::from_utf8_lossy(c).into_owned(),
        })
    } else if tag == context_constructed(1) {
        // domain-specific
        let mut dd = Decoder::new(c);
        let domain = dd.expect(TAG_VISIBLE_STRING)?;
        let item = dd.expect(TAG_VISIBLE_STRING)?;
        Ok(VarRef {
            domain: String::from_utf8_lossy(domain).into_owned(),
            item: String::from_utf8_lossy(item).into_owned(),
        })
    } else {
        Err(Error::protocol(format!("unexpected ObjectName tag {tag}")))
    }
}

/// Decodes a Read-Response into its access results.
fn parse_read_response(resp: &[u8]) -> Result<Vec<Value>> {
    let mut dec = Decoder::new(resp);
    let content = dec.expect(context_constructed(SVC_READ))?;
    let mut inner = Decoder::new(content);
    // An optional echoed variableAccessSpecification [0], then
    // listOfAccessResult [1].
    inner.optional(context_constructed(0))?;
    let ar_content = inner.expect(context_constructed(1))?;
    let mut values = Vec::new();
    let mut ar = Decoder::new(ar_content);
    while ar.more() {
        values.push(decode_access_result(&mut ar)?);
    }
    Ok(values)
}

/// Decodes a Read-Response, returning the echoed access specification's
/// variable references when the server supplied them.
fn parse_read_response_with_spec(resp: &[u8]) -> Result<(Vec<VarRef>, Vec<Value>)> {
    let mut dec = Decoder::new(resp);
    let content = dec.expect(context_constructed(SVC_READ))?;
    let mut inner = Decoder::new(content);

    let mut refs = Vec::new();
    if let Some(spec_content) = inner.optional(context_constructed(0))? {
        let mut sd = Decoder::new(spec_content);
        // Only the listOfVariable [0] alternative names members individually.
        if let Ok(Some(list_content)) = sd.optional(context_constructed(0)) {
            let mut ld = Decoder::new(list_content);
            while ld.more() {
                let Ok(entry) = ld.expect(TAG_SEQUENCE) else {
                    break;
                };
                let mut ed = Decoder::new(entry);
                let Ok(name_content) = ed.expect(context_constructed(0)) else {
                    break;
                };
                let Ok(r) = parse_object_name(name_content) else {
                    break;
                };
                refs.push(r);
            }
        }
    }

    let ar_content = inner.expect(context_constructed(1))?;
    let mut values = Vec::new();
    let mut ar = Decoder::new(ar_content);
    while ar.more() {
        values.push(decode_access_result(&mut ar)?);
    }
    Ok((refs, values))
}

impl Conn {
    /// Issues the Identify service and returns the vendor, model and revision.
    pub async fn identify(&self) -> Result<(String, String, String)> {
        // identify [2] IMPLICIT Identify-Request ::= NULL, which is a
        // primitive empty element (0x82), not a constructed one.
        let resp = self
            .call_inner(prim(context_primitive(SVC_IDENTIFY), Vec::new()))
            .await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_IDENTIFY))?;
        let mut inner = Decoder::new(content);
        let mut out = [String::new(), String::new(), String::new()];
        for (i, slot) in out.iter_mut().enumerate() {
            if let Some(v) = inner.optional(context_primitive(i as u32))? {
                *slot = String::from_utf8_lossy(v).into_owned();
            }
        }
        let [vendor, model, revision] = out;
        Ok((vendor, model, revision))
    }

    /// Retrieves the names of the given object class, optionally scoped to a
    /// domain, following continuation until the list is complete.
    pub async fn get_name_list(
        &self,
        class: ObjectClass,
        domain: &str,
    ) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let mut after = String::new();
        loop {
            let (batch, more) = self.get_name_list_page(class, domain, &after).await?;
            let last = batch.last().cloned();
            names.extend(batch);
            match (more, last) {
                (true, Some(l)) => after = l,
                _ => return Ok(names),
            }
        }
    }

    async fn get_name_list_page(
        &self,
        class: ObjectClass,
        domain: &str,
        after: &str,
    ) -> Result<(Vec<String>, bool)> {
        // GetNameList-Request ::= SEQUENCE {
        //   objectClass [0] ObjectClass,
        //   objectScope [1] CHOICE { vmdSpecific [0] NULL,
        //                            domainSpecific [1] Identifier,
        //                            aaSpecific [2] NULL },
        //   continueAfter [2] Identifier OPTIONAL }
        let mut req = cons(
            context_constructed(SVC_GET_NAME_LIST),
            [cons(
                context_constructed(0),
                [int_elem(context_primitive(0), class as i64)],
            )],
        );
        req.push(if domain.is_empty() {
            cons(context_constructed(1), [prim(context_primitive(0), vec![])])
        } else {
            cons(
                context_constructed(1),
                [prim(context_primitive(1), domain.as_bytes().to_vec())],
            )
        });
        if !after.is_empty() {
            req.push(prim(context_primitive(2), after.as_bytes().to_vec()));
        }

        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_GET_NAME_LIST))?;
        let mut inner = Decoder::new(content);
        // GetNameList-Response ::= SEQUENCE {
        //   listOfIdentifier [0] SEQUENCE OF Identifier,
        //   moreFollows [1] BOOLEAN DEFAULT TRUE }
        let list_content = inner.expect(context_constructed(0))?;
        let mut names = Vec::new();
        let mut ld = Decoder::new(list_content);
        while ld.more() {
            let id = ld.expect(TAG_VISIBLE_STRING)?;
            names.push(String::from_utf8_lossy(id).into_owned());
        }
        let mut more = true; // DEFAULT TRUE
        if let Some(mf) = inner.optional(context_primitive(1))? {
            more = asn1::decode_bool(mf).unwrap_or(true);
        }
        Ok((names, more))
    }

    /// Reads one or more variables of a single domain and returns their values
    /// in order.
    ///
    /// Per-element failures come back as [`Value::DataAccessError`] rather
    /// than failing the whole call.
    pub async fn read(&self, domain: &str, items: &[&str]) -> Result<Vec<Value>> {
        if items.is_empty() {
            return Err(Error::protocol("read requires at least one item"));
        }
        let refs: Vec<VarRef> = items.iter().map(|i| VarRef::new(domain, *i)).collect();
        self.read_refs(&refs).await
    }

    /// Reads variables that may span several domains and VMD scope in one
    /// request.
    ///
    /// [`read`](Conn::read) applies a single domain to every item, which
    /// cannot express a dataset whose members mix scopes; a real ICCP dataset
    /// does exactly that.
    pub async fn read_refs(&self, refs: &[VarRef]) -> Result<Vec<Value>> {
        if refs.is_empty() {
            return Err(Error::protocol("read_refs requires at least one reference"));
        }
        let list = cons(
            context_constructed(0), // listOfVariable [0]
            refs.iter().map(|r| variable_entry(&r.domain, &r.item)),
        );
        // ReadRequest.variableAccessSpecification is [1] EXPLICIT in the MMS
        // module IEC 61850 uses, unlike WriteRequest where it is untagged.
        let vas = cons(context_constructed(1), [list]);
        let resp = self
            .call_inner(cons(context_constructed(SVC_READ), [vas]))
            .await?;
        parse_read_response(&resp)
    }

    /// Writes values to the named domain variables and returns a per-item
    /// result: `Ok(())` on success, or the server's [`DataAccessError`].
    pub async fn write(
        &self,
        domain: &str,
        items: &[&str],
        values: &[Value],
    ) -> Result<Vec<std::result::Result<(), DataAccessError>>> {
        if items.len() != values.len() {
            return Err(Error::protocol("write items/values length mismatch"));
        }
        let list = cons(
            context_constructed(0),
            items.iter().map(|i| variable_entry(domain, i)),
        );
        let data = cons(
            context_constructed(0), // listOfData [0]
            values.iter().filter_map(super::data_element),
        );
        // Write-Request ::= SEQUENCE { variableAccessSpecification,
        //                              listOfData [0] }
        // The access specification is untagged here; only ReadRequest wraps it.
        let resp = self
            .call_inner(cons(context_constructed(SVC_WRITE), [list, data]))
            .await?;

        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_WRITE))?;
        // Write-Response ::= SEQUENCE OF CHOICE {
        //   failure [0] DataAccessError, success [1] NULL }
        let mut results = Vec::new();
        let mut inner = Decoder::new(content);
        while inner.more() {
            let (tag, c) = inner.read_tlv()?;
            if tag == context_primitive(0) {
                let code = asn1::decode_uint(c).unwrap_or(0) as u8;
                results.push(Err(DataAccessError::from_code(code)));
            } else {
                results.push(Ok(()));
            }
        }
        Ok(results)
    }

    /// Retrieves the [`TypeSpec`] of a domain variable.
    ///
    /// Clients use it to reconstruct a server's data model when no SCL file is
    /// available.
    pub async fn get_variable_access_attributes(
        &self,
        domain: &str,
        item: &str,
    ) -> Result<TypeSpec> {
        Ok(self
            .get_variable_access_attributes_raw(domain, item)
            .await?
            .0)
    }

    /// Retrieves a variable's TypeSpecification as both the decoded form and
    /// the raw BER octets the server sent.
    ///
    /// A proxy standing in for the server replays those octets verbatim.
    /// Decoding and re-encoding is close to lossless but not exactly so (a
    /// server may use a non-minimal integer length, or a form this crate
    /// normalises), and "close" is not good enough when a client validates the
    /// type against its own configuration.
    pub async fn get_variable_access_attributes_raw(
        &self,
        domain: &str,
        item: &str,
    ) -> Result<(TypeSpec, Vec<u8>)> {
        // GetVariableAccessAttributes-Request ::= CHOICE {
        //   name [0] ObjectName, address [1] Address }
        let req = cons(
            context_constructed(SVC_GET_VARIABLE_ACCESS),
            [cons(context_constructed(0), [object_name(domain, item)])],
        );
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_GET_VARIABLE_ACCESS))?;
        // GetVariableAccessAttributes-Response ::= SEQUENCE {
        //   mmsDeletable [0] IMPLICIT BOOLEAN,
        //   address [1] EXPLICIT Address OPTIONAL,
        //   typeSpecification [2] EXPLICIT TypeSpecification }
        //
        // The type specification is at [2], not [1]: reading [1] finds the
        // optional address instead and every model retrieval fails.
        let mut inner = Decoder::new(content);
        inner.optional(context_primitive(0))?;
        inner.optional(context_constructed(1))?;
        let ts_content = inner.expect(context_constructed(2))?;
        let raw = ts_content.to_vec();
        let ts = decode_type_spec(&mut Decoder::new(ts_content))?;
        Ok((ts, raw))
    }

    /// Reads all members of a named variable list (a dataset) and returns
    /// their values in order.
    pub async fn read_named_variable_list(
        &self,
        domain: &str,
        list_name: &str,
    ) -> Result<Vec<Value>> {
        // A Read-Request whose variableAccessSpecification is
        // variableListName [1].
        let vas = cons(
            context_constructed(1),
            [cons(context_constructed(1), [object_name(domain, list_name)])],
        );
        let resp = self
            .call_inner(cons(context_constructed(SVC_READ), [vas]))
            .await?;
        parse_read_response(&resp)
    }

    /// Reads a named variable list and asks the server to echo the access
    /// specification, so the caller learns which members the values correspond
    /// to without a separate attributes round trip.
    ///
    /// Servers may omit the specification even when asked; the returned
    /// references are then empty.
    pub async fn read_named_variable_list_with_spec(
        &self,
        domain: &str,
        list_name: &str,
    ) -> Result<(Vec<VarRef>, Vec<Value>)> {
        let vas = cons(
            context_constructed(1),
            [cons(context_constructed(1), [object_name(domain, list_name)])],
        );
        let req = cons(
            context_constructed(SVC_READ),
            [
                bool_elem(context_primitive(0), true), // specificationWithResult
                vas,
            ],
        );
        let resp = self.call_inner(req).await?;
        parse_read_response_with_spec(&resp)
    }

    /// Creates a named variable list (dataset) from the given members.
    pub async fn define_named_variable_list(
        &self,
        domain: &str,
        list_name: &str,
        members: &[VarRef],
    ) -> Result<()> {
        let list = cons(
            context_constructed(1), // listOfVariable [1]
            members.iter().map(|m| {
                cons(
                    TAG_SEQUENCE,
                    [cons(context_constructed(0), [object_name(&m.domain, &m.item)])],
                )
            }),
        );
        // DefineNamedVariableList-Request ::= SEQUENCE {
        //   variableListName ObjectName, listOfVariable [1] SEQUENCE OF ... }
        let req = cons(
            context_constructed(SVC_DEFINE_NAMED_VAR_LIST),
            [object_name(domain, list_name), list],
        );
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        if dec
            .expect(context_constructed(SVC_DEFINE_NAMED_VAR_LIST))
            .is_err()
        {
            // Some servers reply with an empty (NULL) response element.
            if !Decoder::new(&resp).peek_is(context_primitive(SVC_DEFINE_NAMED_VAR_LIST)) {
                return Err(Error::protocol("unexpected defineNamedVariableList response"));
            }
        }
        Ok(())
    }

    /// Deletes a named variable list (dataset).
    pub async fn delete_named_variable_list(
        &self,
        domain: &str,
        list_name: &str,
    ) -> Result<()> {
        // DeleteNamedVariableList-Request ::= SEQUENCE {
        //   scopeOfDelete [0] INTEGER DEFAULT specific,
        //   listOfVariableListName [1] SEQUENCE OF ObjectName OPTIONAL, ... }
        let req = cons(
            context_constructed(SVC_DELETE_NAMED_VAR_LIST),
            [cons(
                context_constructed(1),
                [object_name(domain, list_name)],
            )],
        );
        self.call_inner(req).await?;
        Ok(())
    }

    /// Returns the member references of a named variable list (dataset).
    pub async fn get_named_variable_list_attributes(
        &self,
        domain: &str,
        list_name: &str,
    ) -> Result<Vec<VarRef>> {
        let req = cons(
            context_constructed(SVC_GET_NAMED_VAR_LIST_ATTR),
            [object_name(domain, list_name)],
        );
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_GET_NAMED_VAR_LIST_ATTR))?;
        let mut inner = Decoder::new(content);
        // GetNamedVariableListAttributes-Response ::= SEQUENCE {
        //   mmsDeletable [0] BOOLEAN, listOfVariable [1] SEQUENCE OF ... }
        inner.optional(context_primitive(0))?;
        let list_content = inner.expect(context_constructed(1))?;
        let mut refs = Vec::new();
        let mut ld = Decoder::new(list_content);
        while ld.more() {
            let entry = ld.expect(TAG_SEQUENCE)?;
            let mut ed = Decoder::new(entry);
            // variableSpecification name [0]
            let spec_content = ed.expect(context_constructed(0))?;
            refs.push(parse_object_name(spec_content)?);
        }
        Ok(refs)
    }
}

// File services (ISO 9506-2 services 72..77). Their tag numbers are above 30,
// so they exercise the high-tag-number form of the BER identifier octets.
impl Conn {
    /// Opens a file for reading and returns the file-read state machine id and
    /// the file size.
    pub async fn file_open(&self, name: &str) -> Result<(i32, u32)> {
        let req = cons(
            context_constructed(SVC_FILE_OPEN),
            [
                // fileName [0] SEQUENCE OF GraphicString
                cons(
                    context_constructed(0),
                    [prim(TAG_GRAPHIC_STRING, name.as_bytes().to_vec())],
                ),
                uint_elem(context_primitive(1), 0), // initialPosition [1]
            ],
        );
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_FILE_OPEN))?;
        let mut inner = Decoder::new(content);
        let id_bytes = inner.expect(context_primitive(0))?; // frsmId [0]
        let id = asn1::decode_int(id_bytes).unwrap_or(0) as i32;
        let mut size = 0u32;
        if let Some(attrs) = inner.optional(context_constructed(1))? {
            let mut ad = Decoder::new(attrs);
            if let Ok(sz) = ad.expect(context_primitive(0)) {
                size = asn1::decode_uint(sz).unwrap_or(0) as u32;
            }
        }
        Ok((id, size))
    }

    /// Reads the next chunk of an open file. The flag is false on the last
    /// chunk.
    pub async fn file_read(&self, frsm_id: i32) -> Result<(Vec<u8>, bool)> {
        let req = int_elem(context_primitive(SVC_FILE_READ), i64::from(frsm_id));
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_FILE_READ))?;
        let mut inner = Decoder::new(content);
        let file_data = inner.expect(context_primitive(0))?; // fileData [0]
        let mut more_follows = true; // DEFAULT TRUE
        if let Some(mf) = inner.optional(context_primitive(1))? {
            more_follows = asn1::decode_bool(mf).unwrap_or(true);
        }
        Ok((file_data.to_vec(), more_follows))
    }

    /// Releases a file-read state machine.
    pub async fn file_close(&self, frsm_id: i32) -> Result<()> {
        let req = int_elem(context_primitive(SVC_FILE_CLOSE), i64::from(frsm_id));
        self.call_inner(req).await?;
        Ok(())
    }

    /// Deletes a file from the server's filestore.
    pub async fn file_delete(&self, name: &str) -> Result<()> {
        let req = cons(
            context_constructed(SVC_FILE_DELETE),
            [cons(
                context_constructed(0),
                [prim(TAG_GRAPHIC_STRING, name.as_bytes().to_vec())],
            )],
        );
        self.call_inner(req).await?;
        Ok(())
    }

    /// Lists directory entries under `path` (empty for the root), following
    /// continuation.
    pub async fn file_directory(&self, path: &str) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        let mut after = String::new();
        loop {
            let (batch, more) = self.file_directory_page(path, &after).await?;
            let last = batch.last().map(|e| e.name.clone());
            entries.extend(batch);
            match (more, last) {
                (true, Some(l)) => after = l,
                _ => return Ok(entries),
            }
        }
    }

    async fn file_directory_page(
        &self,
        path: &str,
        after: &str,
    ) -> Result<(Vec<FileEntry>, bool)> {
        let mut req = cons(context_constructed(SVC_FILE_DIRECTORY), []);
        if !path.is_empty() {
            req.push(cons(
                context_constructed(0),
                [prim(TAG_GRAPHIC_STRING, path.as_bytes().to_vec())],
            ));
        }
        if !after.is_empty() {
            req.push(cons(
                context_constructed(1),
                [prim(TAG_GRAPHIC_STRING, after.as_bytes().to_vec())],
            ));
        }
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_FILE_DIRECTORY))?;
        let mut inner = Decoder::new(content);
        // listOfDirectoryEntry [0] explicitly wraps a SEQUENCE OF
        // DirectoryEntry.
        let list_content = inner.expect(context_constructed(0))?;
        let seq_of = Decoder::new(list_content).expect(TAG_SEQUENCE)?;
        let mut entries = Vec::new();
        let mut ld = Decoder::new(seq_of);
        while ld.more() {
            let entry_content = ld.expect(TAG_SEQUENCE)?;
            entries.push(parse_dir_entry(entry_content)?);
        }
        let mut more = false;
        if let Some(mf) = inner.optional(context_primitive(1))? {
            more = asn1::decode_bool(mf).unwrap_or(false);
        }
        Ok((entries, more))
    }
}

fn parse_dir_entry(content: &[u8]) -> Result<FileEntry> {
    let mut dec = Decoder::new(content);
    let mut e = FileEntry::default();
    // fileName [0] SEQUENCE OF GraphicString
    let name_seq = dec.expect(context_constructed(0))?;
    if let Ok(name) = Decoder::new(name_seq).expect(TAG_GRAPHIC_STRING) {
        e.name = String::from_utf8_lossy(name).into_owned();
    }
    // fileAttributes [1] { sizeOfFile [0] Unsigned32,
    //                      lastModified [1] GraphicString }
    if let Some(attrs) = dec.optional(context_constructed(1))? {
        let mut ad = Decoder::new(attrs);
        if let Ok(sz) = ad.expect(context_primitive(0)) {
            e.size = asn1::decode_uint(sz).unwrap_or(0) as u32;
        }
        if let Some(lm) = ad.optional(context_primitive(1))? {
            e.last_modified = parse_generalized_time(&String::from_utf8_lossy(lm));
        }
    }
    Ok(e)
}

/// Parses the ASN.1 GeneralizedTime used for file timestamps
/// (`YYYYMMDDHHMMSS[.sss]Z`), tolerating a missing zone.
fn parse_generalized_time(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    if s.len() < 14 || !s.as_bytes()[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let mo: u32 = s[4..6].parse().ok()?;
    let d: u32 = s[6..8].parse().ok()?;
    let h: i64 = s[8..10].parse().ok()?;
    let mi: i64 = s[10..12].parse().ok()?;
    let sec: i64 = s[12..14].parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let secs = time_util::days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec;
    let mut nanos = 0u32;
    if let Some(rest) = s.get(14..) {
        if let Some(frac) = rest.strip_prefix('.') {
            let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                let mut scaled = String::from(&digits[..digits.len().min(9)]);
                while scaled.len() < 9 {
                    scaled.push('0');
                }
                nanos = scaled.parse().unwrap_or(0);
            }
        }
    }
    Some(time_util::from_unix(secs, nanos))
}

// Journal (log) services.
impl Conn {
    /// Queries a journal (log) for entries in the inclusive time range.
    pub async fn read_journal_by_time(
        &self,
        domain: &str,
        item: &str,
        start: SystemTime,
        end: SystemTime,
    ) -> Result<Vec<JournalEntry>> {
        let req = cons(
            context_constructed(SVC_READ_JOURNAL),
            [
                journal_name(domain, item),
                // rangeStartSpecification [1]
                cons(
                    context_constructed(1),
                    [prim(context_primitive(0), binary_time_bytes(start))],
                ),
                // rangeStopSpecification [2]
                cons(
                    context_constructed(2),
                    [prim(context_primitive(0), binary_time_bytes(end))],
                ),
            ],
        );
        self.read_journal(req).await
    }

    /// Queries a journal for entries after the given time and entry id, for
    /// gap-free continuation.
    pub async fn read_journal_after(
        &self,
        domain: &str,
        item: &str,
        after: SystemTime,
        entry_id: &[u8],
    ) -> Result<Vec<JournalEntry>> {
        let req = cons(
            context_constructed(SVC_READ_JOURNAL),
            [
                journal_name(domain, item),
                // entryToStartAfter [3]
                cons(
                    context_constructed(3),
                    [
                        prim(context_primitive(0), binary_time_bytes(after)),
                        prim(context_primitive(1), entry_id.to_vec()),
                    ],
                ),
            ],
        );
        self.read_journal(req).await
    }

    async fn read_journal(&self, req: Element) -> Result<Vec<JournalEntry>> {
        let resp = self.call_inner(req).await?;
        let mut dec = Decoder::new(&resp);
        let content = dec.expect(context_constructed(SVC_READ_JOURNAL))?;
        let mut inner = Decoder::new(content);
        let list_content = inner.expect(context_constructed(0))?; // listOfJournalEntry [0]
        let mut entries = Vec::new();
        let mut ld = Decoder::new(list_content);
        while ld.more() {
            let entry_content = ld.expect(TAG_SEQUENCE)?;
            entries.push(parse_journal_entry(entry_content)?);
        }
        Ok(entries)
    }
}

fn journal_name(domain: &str, item: &str) -> Element {
    cons(
        context_constructed(0), // journalName [0]
        [cons(
            context_constructed(1), // objectId [1] domain-specific
            [
                prim(TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
                prim(TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
            ],
        )],
    )
}

fn binary_time_bytes(t: SystemTime) -> Vec<u8> {
    Value::binary_time(t).bytes().to_vec()
}

fn parse_journal_entry(content: &[u8]) -> Result<JournalEntry> {
    let mut dec = Decoder::new(content);
    let mut e = JournalEntry::default();
    while dec.more() {
        let (tag, c) = dec.read_tlv()?;
        if tag == context_primitive(0) {
            e.entry_id = c.to_vec();
        } else if tag == context_constructed(2) {
            parse_entry_content(c, &mut e);
        }
    }
    Ok(e)
}

fn parse_entry_content(content: &[u8], e: &mut JournalEntry) {
    let mut dec = Decoder::new(content);
    while dec.more() {
        let Ok((tag, c)) = dec.read_tlv() else {
            return;
        };
        if tag == context_primitive(0) {
            // occurenceTime, carried as a BinaryTime
            if c.len() == 4 || c.len() == 6 {
                e.occurrence_time = Value::BinaryTime(c.to_vec()).time();
            }
        } else if tag == context_constructed(2) {
            parse_journal_variables(c, e);
        }
    }
}

fn parse_journal_variables(content: &[u8], e: &mut JournalEntry) {
    // Each journal variable is a SEQUENCE { variableTag GraphicString,
    // valueSpecification [1] Data }.
    let mut dec = Decoder::new(content);
    while dec.more() {
        let Ok((tag, c)) = dec.read_tlv() else {
            return;
        };
        if tag != TAG_SEQUENCE && tag != context_constructed(1) {
            continue;
        }
        let mut jv = JournalVariable {
            tag: String::new(),
            value: None,
        };
        let mut vd = Decoder::new(c);
        while vd.more() {
            let Ok((t, vc)) = vd.read_tlv() else {
                break;
            };
            if t == TAG_GRAPHIC_STRING || t == TAG_VISIBLE_STRING || t == context_primitive(0) {
                jv.tag = String::from_utf8_lossy(vc).into_owned();
            } else if t == context_constructed(1) {
                // valueSpecification wraps a Data
                if let Ok(v) = super::decode_data(&mut Decoder::new(vc)) {
                    jv.value = Some(v);
                }
            }
        }
        if !jv.tag.is_empty() || jv.value.is_some() {
            e.variables.push(jv);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_round_trip_in_both_scopes() {
        let domain_specific = object_name("ied1LD0", "GGIO1$MX$AnIn1").encode();
        let r = parse_object_name(&domain_specific).unwrap();
        assert_eq!(r, VarRef::new("ied1LD0", "GGIO1$MX$AnIn1"));
        assert_eq!(r.to_string(), "ied1LD0/GGIO1$MX$AnIn1");

        let vmd_specific = object_name("", "SomeGlobal").encode();
        let r = parse_object_name(&vmd_specific).unwrap();
        assert_eq!(r.domain, "");
        assert_eq!(r.item, "SomeGlobal");
    }

    #[test]
    fn an_unexpected_object_name_alternative_is_rejected() {
        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, context_constructed(7), &[]);
        assert!(parse_object_name(&buf).is_err());
        assert!(parse_object_name(&[]).is_err());
    }

    /// The read and write requests tag the access specification differently:
    /// ReadRequest wraps it in an explicit [1], WriteRequest leaves the CHOICE
    /// tags showing through. Encoding both the same way makes one of the two
    /// services fail against every conforming server.
    #[test]
    fn read_wraps_the_access_specification_but_write_does_not() {
        let list = cons(
            context_constructed(0),
            [variable_entry("LD", "GGIO1$ST$Ind1")],
        );
        let read = cons(
            context_constructed(SVC_READ),
            [cons(context_constructed(1), [list.clone()])],
        )
        .encode();
        let mut dec = Decoder::new(&read);
        let content = dec.expect(context_constructed(SVC_READ)).unwrap();
        assert!(
            Decoder::new(content).peek_is(context_constructed(1)),
            "ReadRequest must wrap the specification in an explicit [1]"
        );

        let data = cons(context_constructed(0), [super::super::data_element(&Value::boolean(true)).unwrap()]);
        let write = cons(context_constructed(SVC_WRITE), [list, data]).encode();
        let mut dec = Decoder::new(&write);
        let content = dec.expect(context_constructed(SVC_WRITE)).unwrap();
        assert!(
            Decoder::new(content).peek_is(context_constructed(0)),
            "WriteRequest must leave the CHOICE tag showing through"
        );
    }

    /// The file services use tag numbers above 30, which need the
    /// high-tag-number form of the identifier octets.
    #[test]
    fn file_service_tags_use_the_high_tag_number_form() {
        let el = int_elem(context_primitive(SVC_FILE_READ), 1).encode();
        assert_eq!(el[0], 0x9f, "leading octet must signal a high tag number");
        assert_eq!(el[1], 73, "the tag number follows in base 128");

        let dir = cons(context_constructed(SVC_FILE_DIRECTORY), []).encode();
        assert_eq!(dir[0], 0xbf);
        assert_eq!(dir[1], 77);
    }

    /// `identify` is a primitive [2] NULL (0x82), not a constructed element.
    #[test]
    fn identify_is_a_primitive_null() {
        let el = prim(context_primitive(SVC_IDENTIFY), Vec::new()).encode();
        assert_eq!(el, vec![0x82, 0x00]);
    }

    #[test]
    fn read_responses_decode_their_access_results() {
        let resp = cons(
            context_constructed(SVC_READ),
            [cons(
                context_constructed(1),
                [
                    super::super::data_element(&Value::float32(230.4)).unwrap(),
                    super::super::data_element(&Value::access_error(
                        DataAccessError::ObjectNonExistent,
                    ))
                    .unwrap(),
                ],
            )],
        )
        .encode();
        let values = parse_read_response(&resp).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].as_f32(), 230.4);
        assert_eq!(
            values[1].as_access_error(),
            Some(DataAccessError::ObjectNonExistent),
            "a per-element failure must not fail the whole read"
        );
    }

    #[test]
    fn a_read_response_with_an_echoed_specification_names_its_members() {
        let spec = cons(
            context_constructed(0),
            [cons(
                context_constructed(0),
                [
                    variable_entry("LD", "GGIO1$ST$Ind1"),
                    variable_entry("LD", "GGIO1$ST$Ind2"),
                ],
            )],
        );
        let results = cons(
            context_constructed(1),
            [
                super::super::data_element(&Value::boolean(true)).unwrap(),
                super::super::data_element(&Value::boolean(false)).unwrap(),
            ],
        );
        let resp = cons(context_constructed(SVC_READ), [spec, results]).encode();
        let (refs, values) = parse_read_response_with_spec(&resp).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], VarRef::new("LD", "GGIO1$ST$Ind1"));
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn generalized_times_parse_with_and_without_a_fraction_or_zone() {
        let t = parse_generalized_time("20260816123045Z").unwrap();
        assert_eq!(
            time_util::format_system_time(t),
            "2026-08-16T12:30:45Z"
        );
        let t = parse_generalized_time("20260816123045.250Z").unwrap();
        assert_eq!(
            time_util::format_system_time(t),
            "2026-08-16T12:30:45.250Z"
        );
        // A missing zone is tolerated and read as UTC.
        assert!(parse_generalized_time("20260816123045").is_some());
        assert!(parse_generalized_time("not-a-time").is_none());
        assert!(parse_generalized_time("").is_none());
    }

    #[test]
    fn directory_entries_decode_their_name_size_and_timestamp() {
        let entry = cons(
            TAG_SEQUENCE,
            [
                cons(
                    context_constructed(0),
                    [prim(TAG_GRAPHIC_STRING, b"COMTRADE/rec001.cfg".to_vec())],
                ),
                cons(
                    context_constructed(1),
                    [
                        uint_elem(context_primitive(0), 4096),
                        prim(context_primitive(1), b"20260816123045Z".to_vec()),
                    ],
                ),
            ],
        )
        .encode();
        // Strip the outer SEQUENCE wrapper to get the entry content.
        let mut dec = Decoder::new(&entry);
        let content = dec.expect(TAG_SEQUENCE).unwrap();
        let e = parse_dir_entry(content).unwrap();
        assert_eq!(e.name, "COMTRADE/rec001.cfg");
        assert_eq!(e.size, 4096);
        assert!(e.last_modified.is_some());
    }
}
