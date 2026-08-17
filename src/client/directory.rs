use crate::mms::ObjectClass;
use crate::model::{Fc, ObjectReference};

use super::{Client, Error, Result};

/// Names a class of ACSI objects that can live inside a logical node.
///
/// It selects what [`Client::logical_node_directory`] browses for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcsiClass {
    /// A data object (IEC 61850-7-2 DATA), the default content of a logical
    /// node.
    DataObject,
    /// A data set (DATA-SET).
    DataSet,
    /// A buffered report control block.
    Brcb,
    /// An unbuffered report control block.
    Urcb,
    /// A log control block.
    Lcb,
    /// A log.
    Log,
    /// The setting group control block.
    Sgcb,
    /// A GOOSE control block.
    GoCb,
    /// A GSSE control block (legacy).
    GsCb,
    /// A multicast sampled value control block.
    Msvcb,
    /// A unicast sampled value control block.
    Usvcb,
}

/// The fixed MMS name of the setting group control block.
const SGCB_NAME: &str = "SGCB";

impl AcsiClass {
    /// Every class [`Client::browse`] looks for when the caller names none.
    pub const ALL: [AcsiClass; 11] = [
        AcsiClass::DataObject,
        AcsiClass::DataSet,
        AcsiClass::Brcb,
        AcsiClass::Urcb,
        AcsiClass::Lcb,
        AcsiClass::Log,
        AcsiClass::Sgcb,
        AcsiClass::GoCb,
        AcsiClass::GsCb,
        AcsiClass::Msvcb,
        AcsiClass::Usvcb,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AcsiClass::DataObject => "DATA",
            AcsiClass::DataSet => "DATA-SET",
            AcsiClass::Brcb => "BRCB",
            AcsiClass::Urcb => "URCB",
            AcsiClass::Lcb => "LCB",
            AcsiClass::Log => "LOG",
            AcsiClass::Sgcb => "SGCB",
            AcsiClass::GoCb => "GoCB",
            AcsiClass::GsCb => "GsCB",
            AcsiClass::Msvcb => "MSVCB",
            AcsiClass::Usvcb => "USVCB",
        }
    }

    /// The functional constraint that carries this control-block class in its
    /// MMS name (IEC 61850-8-1).
    ///
    /// The classes that are not named variables at all (data sets and logs)
    /// have none, as does [`AcsiClass::DataObject`], which is defined by
    /// exclusion.
    fn constraint(self) -> Option<Fc> {
        let fc = match self {
            AcsiClass::Brcb => Fc::Br,
            AcsiClass::Urcb => Fc::Rp,
            AcsiClass::Lcb => Fc::Lg,
            // The SGCB lives under SP, as "LN$SP$SGCB"; other SP names are
            // ordinary set points, so the name has to be checked too.
            AcsiClass::Sgcb => Fc::Sp,
            AcsiClass::GoCb => Fc::Go,
            AcsiClass::GsCb => Fc::Gs,
            AcsiClass::Msvcb => Fc::Ms,
            AcsiClass::Usvcb => Fc::Us,
            _ => return None,
        };
        Some(fc)
    }

    /// Reports whether an object named under `fc` belongs to this class.
    fn holds(self, fc: Fc, name: &str) -> bool {
        match self {
            AcsiClass::DataObject => {
                // Everything that is not a control block. The SGCB shares its
                // constraint with ordinary set points and is told apart by
                // its name.
                !is_control_block_fc(fc) && !(fc == Fc::Sp && name == SGCB_NAME)
            }
            AcsiClass::Sgcb => fc == Fc::Sp && name == SGCB_NAME,
            other => other.constraint() == Some(fc),
        }
    }
}

impl std::fmt::Display for AcsiClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The functional constraints that carry control blocks rather than data.
fn is_control_block_fc(fc: Fc) -> bool {
    matches!(
        fc,
        Fc::Br | Fc::Rp | Fc::Lg | Fc::Go | Fc::Gs | Fc::Ms | Fc::Us
    )
}

/// One object found by [`Client::browse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Addresses the object, ready for `get_rcb`, `read_data_set`,
    /// `setting_groups`, `query_log_by_time` or `read`.
    ///
    /// It is the MMS item ID with `$` written as `.`, so a control block keeps
    /// its functional constraint (`LD/LLN0.RP.urcb01`) and a data object does
    /// not (`LD/GGIO1.SPCSO1`), the constraint being a separate argument
    /// there.
    pub reference: ObjectReference,
    /// The ACSI class the object was matched as.
    pub class: AcsiClass,
}

impl Client {
    /// Returns the names of the objects of one ACSI class inside a logical
    /// node, addressed as `LD/LN`.
    ///
    /// This is the ACSI `GetLogicalNodeDirectory`, derived from the MMS name
    /// lists: the names an IED reports are flat MMS item IDs, and the class of
    /// each is carried by its functional constraint, so the browse is a filter
    /// over `GetNameList` rather than a service of its own.
    ///
    /// The names are the bare object names (`Pos`, `urcb01`, `Events`); build a
    /// reference with [`ObjectReference::child`]. Order follows the server's,
    /// deduplicated. An empty result is not an error: a logical node need not
    /// hold any object of a given class.
    pub async fn logical_node_directory(
        &self,
        ln: impl Into<ObjectReference>,
        class: AcsiClass,
    ) -> Result<Vec<String>> {
        let ln = ln.into();
        let (domain, ln_name) = (ln.ld(), ln.ln());
        if domain.is_empty() || ln_name.is_empty() {
            return Err(Error::client(format!(
                "logical node reference {ln:?} must be LD/LN"
            )));
        }

        // Data sets are MMS named variable lists and logs are MMS journals;
        // everything else is a named variable distinguished by its constraint.
        match class {
            AcsiClass::DataSet => {
                let names = self
                    .mms()
                    .get_name_list(ObjectClass::NamedVariableList, domain)
                    .await?;
                Ok(names_under(&names, ln_name))
            }
            AcsiClass::Log => {
                let names = self
                    .mms()
                    .get_name_list(ObjectClass::Journal, domain)
                    .await?;
                Ok(names_under(&names, ln_name))
            }
            _ => {
                let names = self
                    .mms()
                    .get_name_list(ObjectClass::NamedVariable, domain)
                    .await?;
                Ok(objects_of_class(&names, ln_name, class))
            }
        }
    }

    /// Returns every object of the given ACSI classes in a logical device, as
    /// references.
    ///
    /// This is the logical-device-wide form of
    /// [`logical_node_directory`](Client::logical_node_directory): one pass
    /// over the device's name list covers all the logical nodes and all the
    /// classes asked for, so browsing several classes costs no more round trips
    /// than browsing one.
    ///
    /// With no class named, it looks for every class. Entries come grouped by
    /// the name list they were found in (variables, then data sets, then logs),
    /// in the server's order. An error from a name list is returned, including
    /// the journal list that backs [`AcsiClass::Log`], which servers without
    /// logging support may refuse: ask for the classes you need.
    pub async fn browse(&self, ld: &str, classes: &[AcsiClass]) -> Result<Vec<DirectoryEntry>> {
        if ld.is_empty() {
            return Err(Error::client("browse needs a logical device name"));
        }
        let classes: &[AcsiClass] = if classes.is_empty() {
            &AcsiClass::ALL
        } else {
            classes
        };
        let want_sets = classes.contains(&AcsiClass::DataSet);
        let want_logs = classes.contains(&AcsiClass::Log);
        let want_vars = classes
            .iter()
            .any(|c| !matches!(c, AcsiClass::DataSet | AcsiClass::Log));

        let mut out: Vec<DirectoryEntry> = Vec::new();
        let mut add = |reference: ObjectReference, class: AcsiClass| {
            if !out.iter().any(|e| e.reference == reference) {
                out.push(DirectoryEntry { reference, class });
            }
        };

        if want_vars {
            let names = self
                .mms()
                .get_name_list(ObjectClass::NamedVariable, ld)
                .await?;
            for n in &names {
                let parts: Vec<&str> = n.split('$').collect();
                if parts.len() < 3 || parts[0].is_empty() || parts[2].is_empty() {
                    continue;
                }
                let Ok(fc) = parts[1].parse::<Fc>() else {
                    continue;
                };
                let (ln, name) = (parts[0], parts[2]);
                for class in classes {
                    // The classes are disjoint, so the first match is the only
                    // one.
                    if matches!(class, AcsiClass::DataSet | AcsiClass::Log)
                        || !class.holds(fc, name)
                    {
                        continue;
                    }
                    let reference = if *class == AcsiClass::DataObject {
                        ObjectReference::new(format!("{ld}/{ln}.{name}"))
                    } else {
                        ObjectReference::new(format!("{ld}/{ln}.{fc}.{name}"))
                    };
                    add(reference, *class);
                    break;
                }
            }
        }
        if want_sets {
            let names = self
                .mms()
                .get_name_list(ObjectClass::NamedVariableList, ld)
                .await?;
            for n in &names {
                if let Some((ln, name)) = n.split_once('$') {
                    if !ln.is_empty() && !name.is_empty() {
                        add(
                            ObjectReference::new(format!("{ld}/{ln}.{name}")),
                            AcsiClass::DataSet,
                        );
                    }
                }
            }
        }
        if want_logs {
            let names = self.mms().get_name_list(ObjectClass::Journal, ld).await?;
            for n in &names {
                if let Some((ln, name)) = n.split_once('$') {
                    if !ln.is_empty() && !name.is_empty() {
                        add(
                            ObjectReference::new(format!("{ld}/{ln}.{name}")),
                            AcsiClass::Log,
                        );
                    }
                }
            }
        }
        Ok(out)
    }

    /// Returns the names of the immediate children of a data object or data
    /// attribute, addressed as `LD/LN.DO[.DA...]`.
    ///
    /// This is the ACSI `GetDataDirectory`, derived from the same name list: an
    /// IED lists every leaf under its functionally-constrained objects, so one
    /// level of the tree is the set of distinct next components.
    ///
    /// `fc` restricts the browse to one functional constraint; [`Fc::All`] (or
    /// [`Fc::None`]) unions the children seen under every constraint, which is
    /// how a data object exposes both its status attributes and its control
    /// ones.
    pub async fn data_directory(
        &self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
    ) -> Result<Vec<String>> {
        let reference = reference.into();
        let domain = reference.ld();
        let path = reference.path();
        if domain.is_empty() || path.len() < 2 {
            return Err(Error::client(format!(
                "data reference {reference:?} must be LD/LN.DO[.DA...]"
            )));
        }
        let names = self
            .mms()
            .get_name_list(ObjectClass::NamedVariable, domain)
            .await?;
        let (ln_name, want) = (path[0], &path[1..]);

        let mut out: Vec<String> = Vec::new();
        for n in &names {
            let parts: Vec<&str> = n.split('$').collect();
            if parts.len() < 3 || parts[0] != ln_name {
                continue;
            }
            let Ok(efc) = parts[1].parse::<Fc>() else {
                continue;
            };
            if fc != Fc::All && fc != Fc::None && efc != fc {
                continue;
            }
            // The entry has to be exactly one component deeper than the
            // reference, below the same path.
            let rest = &parts[2..];
            if rest.len() != want.len() + 1 || !rest.starts_with(want) {
                continue;
            }
            let child = rest[rest.len() - 1];
            if !out.iter().any(|e| e == child) {
                out.push(child.to_string());
            }
        }
        Ok(out)
    }
}

/// Picks the objects of one class out of a domain's variable name list.
fn objects_of_class(names: &[String], ln: &str, class: AcsiClass) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let parts: Vec<&str> = n.split('$').collect();
        // "LN" and "LN$FC" are the bare node and constraint entries; objects
        // start at "LN$FC$Name", and members ("LN$RP$urcb01$RptID") name the
        // same object again.
        if parts.len() < 3 || parts[0] != ln {
            continue;
        }
        let Ok(fc) = parts[1].parse::<Fc>() else {
            continue;
        };
        let name = parts[2];
        if name.is_empty() || !class.holds(fc, name) || out.iter().any(|e| e == name) {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

/// Returns the entries of an `LN$Name` list that belong to `ln`, stripped of
/// the logical node prefix.
fn names_under(names: &[String], ln: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let Some((node, name)) = n.split_once('$') else {
            continue;
        };
        if node != ln || name.is_empty() || out.iter().any(|e| e == name) {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The variable name list a typical IED reports for one logical device.
    fn sample_names() -> Vec<String> {
        [
            "LLN0",
            "LLN0$ST",
            "LLN0$ST$Beh$stVal",
            "LLN0$CF$Beh$ctlModel",
            "LLN0$RP$urcb01",
            "LLN0$RP$urcb01$RptID",
            "LLN0$RP$urcb01$RptEna",
            "LLN0$BR$brcb01",
            "LLN0$BR$brcb01$EntryID",
            "LLN0$LG$lcb01",
            "LLN0$GO$gcb01",
            "LLN0$MS$msvcb01",
            "LLN0$SP$SGCB",
            "LLN0$SP$SGCB$NumOfSG",
            "LLN0$SP$SomeSetpoint",
            "GGIO1$ST$Ind1$stVal",
            "GGIO1$ST$Ind1$q",
            "GGIO1$ST$Ind1$t",
            "GGIO1$MX$AnIn1$mag$f",
            "GGIO1$MX$AnIn1$q",
            "GGIO1$CO$SPCSO1$Oper$ctlVal",
            "GGIO1$CF$SPCSO1$ctlModel",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn control_blocks_are_matched_by_their_functional_constraint() {
        let names = sample_names();
        assert_eq!(
            objects_of_class(&names, "LLN0", AcsiClass::Urcb),
            ["urcb01"]
        );
        assert_eq!(
            objects_of_class(&names, "LLN0", AcsiClass::Brcb),
            ["brcb01"]
        );
        assert_eq!(objects_of_class(&names, "LLN0", AcsiClass::Lcb), ["lcb01"]);
        assert_eq!(objects_of_class(&names, "LLN0", AcsiClass::GoCb), ["gcb01"]);
        assert_eq!(
            objects_of_class(&names, "LLN0", AcsiClass::Msvcb),
            ["msvcb01"]
        );
        // A class the node has none of yields nothing, not an error.
        assert!(objects_of_class(&names, "LLN0", AcsiClass::Usvcb).is_empty());
    }

    /// The SGCB shares functional constraint SP with ordinary set points, so
    /// only its name tells them apart. Getting this wrong reports every set
    /// point as a setting group control block, or loses the SGCB entirely.
    #[test]
    fn the_setting_group_control_block_is_told_apart_by_name() {
        let names = sample_names();
        assert_eq!(objects_of_class(&names, "LLN0", AcsiClass::Sgcb), ["SGCB"]);
        let data = objects_of_class(&names, "LLN0", AcsiClass::DataObject);
        assert!(
            data.contains(&"SomeSetpoint".to_string()),
            "an SP set point is data"
        );
        assert!(!data.contains(&"SGCB".to_string()), "the SGCB is not data");
    }

    #[test]
    fn data_objects_exclude_every_control_block() {
        let data = objects_of_class(&sample_names(), "LLN0", AcsiClass::DataObject);
        assert_eq!(data, ["Beh", "SomeSetpoint"]);
        for cb in ["urcb01", "brcb01", "lcb01", "gcb01", "msvcb01"] {
            assert!(!data.contains(&cb.to_string()), "{cb} is a control block");
        }
    }

    #[test]
    fn an_object_seen_under_several_names_is_reported_once() {
        // urcb01 appears three times in the name list, as the block and two
        // of its members.
        assert_eq!(
            objects_of_class(&sample_names(), "LLN0", AcsiClass::Urcb).len(),
            1
        );
    }

    #[test]
    fn data_set_and_journal_lists_are_stripped_of_their_node_prefix() {
        let names: Vec<String> = ["LLN0$Events", "LLN0$Measurements", "GGIO1$Other"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(names_under(&names, "LLN0"), ["Events", "Measurements"]);
        assert_eq!(names_under(&names, "GGIO1"), ["Other"]);
        assert!(names_under(&names, "NOPE").is_empty());
        // An entry with no separator belongs to no node.
        assert!(names_under(&["bare".to_string()], "bare").is_empty());
    }

    #[test]
    fn classes_render_their_acsi_names() {
        assert_eq!(AcsiClass::DataObject.to_string(), "DATA");
        assert_eq!(AcsiClass::DataSet.to_string(), "DATA-SET");
        assert_eq!(AcsiClass::Brcb.to_string(), "BRCB");
        assert_eq!(AcsiClass::Sgcb.to_string(), "SGCB");
        // Every class is distinct.
        let mut seen: Vec<&str> = AcsiClass::ALL.iter().map(|c| c.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), AcsiClass::ALL.len());
    }

    #[test]
    fn the_classes_partition_the_name_list() {
        // Every object in the sample belongs to exactly one class, or the
        // browse would report it twice or not at all.
        let names = sample_names();
        for n in &names {
            let parts: Vec<&str> = n.split('$').collect();
            if parts.len() < 3 {
                continue;
            }
            let Ok(fc) = parts[1].parse::<Fc>() else {
                continue;
            };
            let matches: Vec<AcsiClass> = AcsiClass::ALL
                .into_iter()
                .filter(|c| {
                    !matches!(c, AcsiClass::DataSet | AcsiClass::Log) && c.holds(fc, parts[2])
                })
                .collect();
            assert_eq!(matches.len(), 1, "{n} matched {matches:?}");
        }
    }
}
