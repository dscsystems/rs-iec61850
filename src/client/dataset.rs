use crate::mms::{VarRef, Value};
use crate::model::{self, Fc, ObjectReference};

use super::{Client, Result};

/// The result of reading a named dataset.
#[derive(Debug, Clone)]
pub struct DataSet {
    pub reference: ObjectReference,
    pub members: Vec<DataSetEntry>,
}

/// One dataset member with its value.
#[derive(Debug, Clone)]
pub struct DataSetEntry {
    pub reference: ObjectReference,
    pub fc: Fc,
    pub value: Option<Value>,
}

impl DataSetEntry {
    /// Names a member without a value, for creating a dataset.
    pub fn new(reference: impl Into<ObjectReference>, fc: Fc) -> DataSetEntry {
        DataSetEntry {
            reference: reference.into(),
            fc,
            value: None,
        }
    }
}

/// Converts an IEC 61850 dataset reference `LD/LN.DataSet` to the MMS
/// `(domain, listName)` pair `LD` and `LN$DataSet`.
pub(crate) fn dataset_ref_to_mms(reference: &ObjectReference) -> (String, String) {
    (reference.ld().to_string(), reference.path().join("$"))
}

impl Client {
    /// Reads all members of a dataset named `LD/LN.DataSetName`.
    ///
    /// The member references come from the server's own definition of the
    /// list, so the values are labelled with what they actually are rather
    /// than with what the caller assumed.
    pub async fn read_data_set(
        &self,
        reference: impl Into<ObjectReference>,
    ) -> Result<DataSet> {
        let reference = reference.into();
        let (domain, list) = dataset_ref_to_mms(&reference);
        let refs = self
            .mms()
            .get_named_variable_list_attributes(&domain, &list)
            .await?;
        let values = self.mms().read_named_variable_list(&domain, &list).await?;

        let mut members = Vec::with_capacity(refs.len());
        for (i, r) in refs.iter().enumerate() {
            let (object_ref, fc) = model::from_mms(&r.domain, &r.item);
            members.push(DataSetEntry {
                reference: object_ref,
                fc,
                value: values.get(i).cloned(),
            });
        }
        Ok(DataSet {
            reference,
            members,
        })
    }

    /// Returns the member references of a dataset without reading its values.
    pub async fn data_set_members(
        &self,
        reference: impl Into<ObjectReference>,
    ) -> Result<Vec<DataSetEntry>> {
        let reference = reference.into();
        let (domain, list) = dataset_ref_to_mms(&reference);
        let refs = self
            .mms()
            .get_named_variable_list_attributes(&domain, &list)
            .await?;
        Ok(refs
            .iter()
            .map(|r| {
                let (object_ref, fc) = model::from_mms(&r.domain, &r.item);
                DataSetEntry {
                    reference: object_ref,
                    fc,
                    value: None,
                }
            })
            .collect())
    }

    /// Creates a dataset `LD/LN.Name` from the given members.
    pub async fn create_data_set(
        &self,
        reference: impl Into<ObjectReference>,
        members: &[DataSetEntry],
    ) -> Result<()> {
        let reference = reference.into();
        let (domain, list) = dataset_ref_to_mms(&reference);
        let refs: Vec<VarRef> = members
            .iter()
            .map(|m| {
                let (d, item) = m.reference.to_mms(m.fc);
                VarRef::new(d, item)
            })
            .collect();
        self.mms()
            .define_named_variable_list(&domain, &list, &refs)
            .await?;
        Ok(())
    }

    /// Deletes a dataset `LD/LN.Name`.
    pub async fn delete_data_set(
        &self,
        reference: impl Into<ObjectReference>,
    ) -> Result<()> {
        let reference = reference.into();
        let (domain, list) = dataset_ref_to_mms(&reference);
        self.mms()
            .delete_named_variable_list(&domain, &list)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dataset lives at "LD/LN.Name" but is addressed on the wire as the
    /// domain "LD" plus the list "LN$Name"; getting the split wrong addresses
    /// a variable rather than a list.
    #[test]
    fn dataset_references_convert_to_the_mms_list_form() {
        let (domain, list) = dataset_ref_to_mms(&"ied1LD0/LLN0.Events".into());
        assert_eq!(domain, "ied1LD0");
        assert_eq!(list, "LLN0$Events");
    }

    #[test]
    fn a_deeper_dataset_path_joins_every_component() {
        let (domain, list) = dataset_ref_to_mms(&"LD/LLN0.Sub.Events".into());
        assert_eq!(domain, "LD");
        assert_eq!(list, "LLN0$Sub$Events");
    }

    #[test]
    fn a_member_entry_carries_its_reference_and_constraint() {
        let e = DataSetEntry::new("ied1LD0/GGIO1.AnIn1", Fc::Mx);
        assert_eq!(e.reference.as_str(), "ied1LD0/GGIO1.AnIn1");
        assert_eq!(e.fc, Fc::Mx);
        assert!(e.value.is_none());
        // And converts back to the MMS form a define request needs.
        let (d, item) = e.reference.to_mms(e.fc);
        assert_eq!((d.as_str(), item.as_str()), ("ied1LD0", "GGIO1$MX$AnIn1"));
    }
}
