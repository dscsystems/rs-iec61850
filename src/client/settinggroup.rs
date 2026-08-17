use crate::mms::Value;
use crate::model::{Fc, ObjectReference};

use super::{Client, Error, Result};

/// A handle to a setting group control block (`LD/LN.SP.SGCB`).
///
/// This is the ACSI mechanism for switching between and editing alternative
/// parameter sets, which protection IEDs use to hold one set of settings per
/// operating configuration.
#[derive(Debug)]
pub struct SettingGroups<'a> {
    client: &'a Client,
    pub reference: ObjectReference,

    pub num_of_sg: u8,
    pub act_sg: u8,
    pub edit_sg: u8,

    domain: String,
    /// `LN$SP$SGCB`.
    item: String,
}

impl Client {
    /// Reads the setting group control block at `reference`.
    ///
    /// `NumOfSG` is mandatory: a block without it is not a setting group
    /// control block, and reporting one would let a caller select groups the
    /// device does not have.
    pub async fn setting_groups(
        &self,
        reference: impl Into<ObjectReference>,
    ) -> Result<SettingGroups<'_>> {
        let reference = reference.into();
        let domain = reference.ld().to_string();
        let item = reference.path().join("$");
        let mut sg = SettingGroups {
            client: self,
            reference,
            num_of_sg: 0,
            act_sg: 0,
            edit_sg: 0,
            domain,
            item,
        };
        sg.num_of_sg = sg.read_attr("NumOfSG").await?.as_u64() as u8;
        if let Ok(v) = sg.read_attr("ActSG").await {
            sg.act_sg = v.as_u64() as u8;
        }
        if let Ok(v) = sg.read_attr("EditSG").await {
            sg.edit_sg = v.as_u64() as u8;
        }
        Ok(sg)
    }
}

impl SettingGroups<'_> {
    async fn read_attr(&self, attr: &str) -> Result<Value> {
        let item = format!("{}${attr}", self.item);
        let vals = self.client.mms().read(&self.domain, &[&item]).await?;
        let Some(v) = vals.into_iter().next() else {
            return Err(Error::client(format!("SGCB attribute {attr} missing")));
        };
        if let Some(code) = v.as_access_error() {
            return Err(code.into());
        }
        Ok(v)
    }

    async fn write_attr(&self, attr: &str, v: Value) -> Result<()> {
        let item = format!("{}${attr}", self.item);
        let results = self.client.mms().write(&self.domain, &[&item], &[v]).await?;
        match results.into_iter().next() {
            Some(Err(code)) => Err(Error::client(format!("SGCB write {attr}: {code}"))),
            _ => Ok(()),
        }
    }

    /// Activates setting group `group` (1..=`num_of_sg`), making its
    /// `SG`-scoped values the ones in effect.
    pub async fn select_active_sg(&mut self, group: u8) -> Result<()> {
        self.check_group(group)?;
        self.write_attr("ActSG", Value::uint8(group)).await?;
        self.act_sg = group;
        Ok(())
    }

    /// Selects the setting group to edit; subsequent reads and writes of
    /// `SE`-scoped attributes address that group.
    pub async fn select_edit_sg(&mut self, group: u8) -> Result<()> {
        self.check_group(group)?;
        self.write_attr("EditSG", Value::uint8(group)).await?;
        self.edit_sg = group;
        Ok(())
    }

    /// Writes a setting value in the currently selected edit group, addressing
    /// an `SE`-constrained attribute such as `LD/PTOC1.OpDlTmms.setVal`.
    pub async fn set_edit_value(
        &self,
        reference: impl Into<ObjectReference>,
        v: Value,
    ) -> Result<()> {
        self.client.write(reference, Fc::Se, v).await
    }

    /// Reads a setting value from the currently selected edit group.
    pub async fn edit_value(&self, reference: impl Into<ObjectReference>) -> Result<Value> {
        self.client.read(reference, Fc::Se).await
    }

    /// Commits the edited values to the edit setting group.
    pub async fn confirm_edit(&self) -> Result<()> {
        self.write_attr("CnfEdit", Value::boolean(true)).await
    }

    /// Rejects a group number the device cannot have.
    fn check_group(&self, group: u8) -> Result<()> {
        if !group_in_range(group, self.num_of_sg) {
            return Err(Error::client(format!(
                "setting group {group} is outside 1..={}",
                self.num_of_sg
            )));
        }
        Ok(())
    }
}

/// Reports whether `group` is one the device can have.
///
/// Groups are numbered from one, so zero is never valid: a device that
/// accepted it would leave the active group undefined. A device that reports
/// no count bounds nothing, so any positive group is passed through to it.
fn group_in_range(group: u8, num_of_sg: u8) -> bool {
    group != 0 && (num_of_sg == 0 || group <= num_of_sg)
}

#[cfg(test)]
mod tests {
    use super::group_in_range;

    #[test]
    fn group_numbers_outside_the_devices_range_are_rejected() {
        assert!(!group_in_range(0, 4), "groups are numbered from one");
        assert!(group_in_range(1, 4));
        assert!(group_in_range(4, 4));
        assert!(!group_in_range(5, 4), "beyond NumOfSG");
    }

    #[test]
    fn a_device_that_does_not_report_a_count_accepts_any_positive_group() {
        assert!(!group_in_range(0, 0));
        assert!(group_in_range(9, 0), "with no declared count, nothing bounds it");
        assert!(group_in_range(255, 0));
    }
}
