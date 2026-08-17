use super::{append_length, append_tag, length_size, tag_size, Tag};

/// A build-time representation of a BER element.
///
/// It exists for the control-plane codecs (MMS, ACSE, presentation) where
/// clarity beats allocation counts; the GOOSE and SV hot paths use the
/// `append_*` helpers directly instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    /// A primitive element carrying content octets.
    Primitive { tag: Tag, value: Vec<u8> },
    /// A constructed element carrying child elements.
    Constructed { tag: Tag, children: Vec<Element> },
    /// A constructed element whose content is already-encoded octets.
    ///
    /// This embeds a nested PDU encoded elsewhere without re-parsing it,
    /// for example an ACSE APDU inside a presentation single-ASN1-type.
    Raw { tag: Tag, content: Vec<u8> },
    /// Pre-encoded complete TLV(s) appended verbatim, with no tag or length
    /// of their own. Use it to place an element encoded elsewhere as a child
    /// of a constructed element.
    Verbatim(Vec<u8>),
}

/// Returns a primitive element.
pub fn prim(tag: Tag, value: impl Into<Vec<u8>>) -> Element {
    Element::Primitive {
        tag,
        value: value.into(),
    }
}

/// Returns a constructed element.
///
/// `None` children are skipped, which lets callers express optional fields
/// inline with [`Element::add`].
pub fn cons(tag: Tag, children: impl IntoIterator<Item = Element>) -> Element {
    let mut tag = tag;
    tag.constructed = true;
    Element::Constructed {
        tag,
        children: children.into_iter().collect(),
    }
}

/// Returns a constructed element with tag `t` whose content is the
/// already-encoded octets in `content` (one or more complete TLVs).
pub fn raw_content(tag: Tag, content: impl Into<Vec<u8>>) -> Element {
    let mut tag = tag;
    tag.constructed = true;
    Element::Raw {
        tag,
        content: content.into(),
    }
}

/// Returns an element that appends the pre-encoded complete TLV(s) in `tlv`
/// verbatim, with no tag or length of its own.
pub fn raw_tlv(tlv: impl Into<Vec<u8>>) -> Element {
    Element::Verbatim(tlv.into())
}

impl Element {
    /// Returns an empty constructed element with tag `t`, ready for
    /// [`add`](Element::add) / [`push`](Element::push).
    pub fn seq(tag: Tag) -> Element {
        cons(tag, [])
    }

    /// Appends a child and returns `self`, for chained construction.
    ///
    /// Has no effect on primitive, raw or verbatim elements.
    // Named for what it does to a constructed element, not for arithmetic;
    // renaming it would make every PDU builder read worse to satisfy a lint.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(mut self, child: Element) -> Element {
        self.push(child);
        self
    }

    /// Appends `child` when it is `Some`, and returns `self`.
    ///
    /// This is how optional PDU fields are expressed inline.
    #[must_use]
    pub fn add_opt(mut self, child: Option<Element>) -> Element {
        if let Some(c) = child {
            self.push(c);
        }
        self
    }

    /// Appends every element of `children` and returns `self`.
    #[must_use]
    pub fn add_all(mut self, children: impl IntoIterator<Item = Element>) -> Element {
        for c in children {
            self.push(c);
        }
        self
    }

    /// Appends a child in place.
    pub fn push(&mut self, child: Element) {
        if let Element::Constructed { children, .. } = self {
            children.push(child);
        }
    }

    /// Returns the element's tag, or `None` for a verbatim element.
    pub fn tag(&self) -> Option<Tag> {
        match self {
            Element::Primitive { tag, .. }
            | Element::Constructed { tag, .. }
            | Element::Raw { tag, .. } => Some(*tag),
            Element::Verbatim(_) => None,
        }
    }

    /// Returns the encoded size of the element's content octets.
    pub fn content_size(&self) -> usize {
        match self {
            Element::Primitive { value, .. } => value.len(),
            Element::Constructed { children, .. } => children.iter().map(Element::size).sum(),
            Element::Raw { content, .. } => content.len(),
            Element::Verbatim(v) => v.len(),
        }
    }

    /// Returns the total encoded size of the element.
    pub fn size(&self) -> usize {
        match self {
            Element::Verbatim(v) => v.len(),
            _ => {
                let n = self.content_size();
                let tag = self.tag().expect("non-verbatim element has a tag");
                tag_size(tag) + length_size(n) + n
            }
        }
    }

    /// Encodes the element onto `dst`.
    pub fn append(&self, dst: &mut Vec<u8>) {
        match self {
            Element::Verbatim(v) => dst.extend_from_slice(v),
            Element::Primitive { tag, value } => {
                append_tag(dst, *tag);
                append_length(dst, value.len());
                dst.extend_from_slice(value);
            }
            Element::Raw { tag, content } => {
                append_tag(dst, *tag);
                append_length(dst, content.len());
                dst.extend_from_slice(content);
            }
            Element::Constructed { tag, children } => {
                let n: usize = children.iter().map(Element::size).sum();
                append_tag(dst, *tag);
                append_length(dst, n);
                for c in children {
                    c.append(dst);
                }
            }
        }
    }

    /// Returns the encoded element as a fresh buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        self.append(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn size_matches_the_encoded_length() {
        let el = cons(
            TAG_SEQUENCE,
            [
                int_elem(TAG_INTEGER, 42),
                prim(TAG_VISIBLE_STRING, b"hello".to_vec()),
                cons(context_constructed(0), [bool_elem(TAG_BOOLEAN, true)]),
            ],
        );
        assert_eq!(el.size(), el.encode().len());
    }

    #[test]
    fn raw_content_wraps_pre_encoded_octets_without_re_parsing() {
        let inner = cons(TAG_SEQUENCE, [int_elem(TAG_INTEGER, 1)]).encode();
        let outer = raw_content(context_constructed(0), inner.clone());
        let mut expected = Vec::new();
        append_tlv(&mut expected, context_constructed(0), &inner);
        assert_eq!(outer.encode(), expected);
    }

    #[test]
    fn verbatim_children_are_spliced_with_no_wrapper() {
        let child = int_elem(TAG_INTEGER, 5).encode();
        let el = cons(TAG_SEQUENCE, [raw_tlv(child.clone())]);
        let mut expected = Vec::new();
        append_tlv(&mut expected, TAG_SEQUENCE, &child);
        assert_eq!(el.encode(), expected);
        assert_eq!(el.size(), expected.len());
    }

    #[test]
    fn add_opt_skips_absent_optional_fields() {
        let with = Element::seq(TAG_SEQUENCE).add_opt(Some(int_elem(TAG_INTEGER, 1)));
        let without = Element::seq(TAG_SEQUENCE).add_opt(None);
        assert_eq!(with.encode(), vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(without.encode(), vec![0x30, 0x00]);
    }

    #[test]
    fn cons_forces_the_constructed_bit() {
        // A caller passing a primitive tag to cons still gets a constructed
        // element, matching the Go builder's behaviour.
        let el = cons(context_primitive(3), [prim(TAG_NULL, vec![])]);
        assert_eq!(el.encode()[0], 0xa3);
    }
}
