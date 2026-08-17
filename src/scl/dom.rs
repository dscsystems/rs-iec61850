//! A minimal XML tree used by the SCL parser.
//!
//! SCL elements are matched by local name so that any SCL namespace revision
//! is accepted, and the documents involved are small enough (tens of kilobytes
//! for an ICD or CID, a few megabytes for a large SCD) that reading the whole
//! tree is simpler and safer than a streaming parser threaded through every
//! element type.

use quick_xml::events::Event;
use quick_xml::Reader;

use super::Error;

/// One XML element.
#[derive(Debug, Clone, Default)]
pub struct Node {
    /// The element's local name, with any namespace prefix stripped.
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// The concatenated character data directly inside the element.
    pub text: String,
    pub children: Vec<Node>,
}

/// Bounds nesting so a hostile or corrupt document cannot exhaust the stack.
const MAX_DEPTH: usize = 256;

impl Node {
    /// Returns the value of the named attribute.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the named attribute, or the empty string when absent.
    pub fn attr_or_empty(&self, name: &str) -> &str {
        self.attr(name).unwrap_or("")
    }

    /// Returns the named attribute as an owned string, empty when absent.
    pub fn attr_string(&self, name: &str) -> String {
        self.attr_or_empty(name).to_string()
    }

    /// Parses the named attribute, falling back to the type's default when it
    /// is absent or unparseable.
    ///
    /// SCL in the wild carries empty and malformed numeric attributes; a
    /// device that publishes `confRev=""` should still load.
    pub fn attr_num<T: std::str::FromStr + Default>(&self, name: &str) -> T {
        self.attr(name)
            .map(str::trim)
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }

    /// Parses an optional boolean attribute with a schema default.
    ///
    /// Several SCL attributes (`gi`, `multicast`, `logEna`) default to true
    /// when omitted, so the default has to be supplied by the caller rather
    /// than assumed false.
    pub fn attr_bool(&self, name: &str, default: bool) -> bool {
        match self.attr(name).map(str::trim) {
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            _ => default,
        }
    }

    /// Returns the first child element with the given local name.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Returns every child element with the given local name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
}

/// Parses an XML document into a tree, returning the root element.
pub fn parse(xml: &str) -> Result<Node, Error> {
    let mut reader = Reader::from_str(xml);
    let config = reader.config_mut();
    config.trim_text(false);
    config.expand_empty_elements = false;
    config.check_end_names = true;

    // The element currently being filled, plus its open ancestors.
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;

    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(Error::Xml(format!(
                    "at position {}: {e}",
                    reader.buffer_position()
                )))
            }
            Ok(Event::Eof) => break,

            Ok(Event::Start(e)) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(Error::Xml(format!("nesting deeper than {MAX_DEPTH}")));
                }
                stack.push(node_from(&e)?);
            }

            Ok(Event::Empty(e)) => {
                let node = node_from(&e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    // An empty root element is a complete (if useless) document.
                    None if root.is_none() => root = Some(node),
                    None => {}
                }
            }

            Ok(Event::End(_)) => {
                let Some(node) = stack.pop() else {
                    return Err(Error::Xml("unbalanced end tag".into()));
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }

            Ok(Event::Text(t)) => {
                if let Some(top) = stack.last_mut() {
                    let decoded = t
                        .unescape()
                        .map_err(|e| Error::Xml(format!("bad character data: {e}")))?;
                    top.text.push_str(&decoded);
                }
            }

            Ok(Event::CData(t)) => {
                // CDATA is literal by definition, so it is taken as-is
                // rather than unescaped.
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(&t));
                }
            }

            // Declarations, comments, processing instructions and doctypes
            // carry nothing the model needs.
            Ok(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(Error::Xml("unclosed element at end of document".into()));
    }
    root.ok_or_else(|| Error::Xml("document has no root element".into()))
}

fn node_from(e: &quick_xml::events::BytesStart<'_>) -> Result<Node, Error> {
    let name = local_name(e.name().as_ref());
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|err| Error::Xml(format!("bad attribute in <{name}>: {err}")))?;
        let key = local_name(a.key.as_ref());
        let value = a
            .unescape_value()
            .map_err(|err| Error::Xml(format!("bad attribute value in <{name}>: {err}")))?
            .into_owned();
        attrs.push((key, value));
    }
    Ok(Node {
        name,
        attrs,
        text: String::new(),
        children: Vec::new(),
    })
}

/// Strips a namespace prefix, so `scl:IED` and `IED` match alike.
fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_and_text_are_read() {
        let doc = parse(
            r#"<SCL version="2007" revision="B">
                 <Header id="demo"/>
                 <IED name="ied1"><AccessPoint name="S1"/></IED>
               </SCL>"#,
        )
        .unwrap();
        assert_eq!(doc.name, "SCL");
        assert_eq!(doc.attr("version"), Some("2007"));
        assert_eq!(doc.child("Header").unwrap().attr("id"), Some("demo"));
        let ied = doc.child("IED").unwrap();
        assert_eq!(ied.attr("name"), Some("ied1"));
        assert_eq!(ied.child("AccessPoint").unwrap().attr("name"), Some("S1"));
    }

    /// Matching by local name is what lets one parser read every SCL
    /// namespace revision.
    #[test]
    fn namespace_prefixes_are_stripped_from_names() {
        let doc = parse(
            r#"<scl:SCL xmlns:scl="http://www.iec.ch/61850/2003/SCL">
                 <scl:IED scl:name="ied1"/>
               </scl:SCL>"#,
        )
        .unwrap();
        assert_eq!(doc.name, "SCL");
        assert_eq!(doc.child("IED").unwrap().attr("name"), Some("ied1"));
    }

    #[test]
    fn character_data_is_collected() {
        let doc = parse(r#"<P type="MAC-Address">01-0C-CD-01-00-01</P>"#).unwrap();
        assert_eq!(doc.text.trim(), "01-0C-CD-01-00-01");

        let doc = parse("<Val><![CDATA[hello]]></Val>").unwrap();
        assert_eq!(doc.text, "hello");
    }

    #[test]
    fn repeated_children_are_all_kept_in_order() {
        let doc = parse(
            r#"<DataSet>
                 <FCDA doName="A"/><FCDA doName="B"/><FCDA doName="C"/>
               </DataSet>"#,
        )
        .unwrap();
        let names: Vec<&str> = doc
            .children_named("FCDA")
            .map(|f| f.attr_or_empty("doName"))
            .collect();
        assert_eq!(names, ["A", "B", "C"]);
    }

    #[test]
    fn schema_defaults_apply_to_absent_boolean_attributes() {
        let doc = parse(r#"<TrgOps dchg="true" period="false"/>"#).unwrap();
        assert!(doc.attr_bool("dchg", false));
        assert!(!doc.attr_bool("period", true));
        // gi defaults to true when omitted.
        assert!(doc.attr_bool("gi", true));
        assert!(!doc.attr_bool("qchg", false));
    }

    #[test]
    fn malformed_numeric_attributes_fall_back_to_the_default() {
        let doc = parse(r#"<ReportControl confRev="" bufTime="oops" intgPd="1000"/>"#).unwrap();
        assert_eq!(doc.attr_num::<u32>("confRev"), 0);
        assert_eq!(doc.attr_num::<u32>("bufTime"), 0);
        assert_eq!(doc.attr_num::<u32>("intgPd"), 1000);
        assert_eq!(doc.attr_num::<u32>("missing"), 0);
    }

    #[test]
    fn comments_and_declarations_are_ignored() {
        let doc = parse(
            r#"<?xml version="1.0" encoding="UTF-8"?>
               <!-- a comment -->
               <SCL><!-- another --><IED name="x"/></SCL>"#,
        )
        .unwrap();
        assert_eq!(doc.name, "SCL");
        assert_eq!(doc.children.len(), 1);
    }

    #[test]
    fn malformed_documents_are_rejected() {
        assert!(parse("").is_err(), "no root element");
        assert!(parse("<SCL>").is_err(), "unclosed element");
        assert!(parse("<SCL></IED>").is_err(), "mismatched end tag");
        assert!(parse("<SCL attr=></SCL>").is_err());
    }

    #[test]
    fn deep_nesting_is_rejected_rather_than_overflowing_the_stack() {
        let deep = "<a>".repeat(MAX_DEPTH + 8);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn entities_in_attributes_and_text_are_unescaped() {
        let doc = parse(r#"<Val desc="a &amp; b">x &lt; y</Val>"#).unwrap();
        assert_eq!(doc.attr("desc"), Some("a & b"));
        assert_eq!(doc.text, "x < y");
    }
}
