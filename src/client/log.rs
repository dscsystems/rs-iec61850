use std::time::SystemTime;

use crate::model::ObjectReference;

use super::{Client, LogEntry, Result};

/// Converts `LD/LN.LG.LogName` to the domain and MMS item `LN$LG$LogName`.
fn log_ref_to_mms(reference: &ObjectReference) -> (String, String) {
    (reference.ld().to_string(), reference.path().join("$"))
}

impl Client {
    /// Returns log entries in the inclusive time range from the log referenced
    /// as `LD/LN.LG.LogName`.
    pub async fn query_log_by_time(
        &self,
        log_ref: impl Into<ObjectReference>,
        start: SystemTime,
        end: SystemTime,
    ) -> Result<Vec<LogEntry>> {
        let (domain, item) = log_ref_to_mms(&log_ref.into());
        Ok(self
            .mms()
            .read_journal_by_time(&domain, &item, start, end)
            .await?)
    }

    /// Returns log entries after the given time and entry id, for gap-free
    /// continuation of a previous query.
    pub async fn query_log_after(
        &self,
        log_ref: impl Into<ObjectReference>,
        after: SystemTime,
        entry_id: &[u8],
    ) -> Result<Vec<LogEntry>> {
        let (domain, item) = log_ref_to_mms(&log_ref.into());
        Ok(self
            .mms()
            .read_journal_after(&domain, &item, after, entry_id)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_references_convert_to_the_mms_item_form() {
        let (domain, item) = log_ref_to_mms(&"ied1LD0/LLN0.LG.EventLog".into());
        assert_eq!(domain, "ied1LD0");
        assert_eq!(item, "LLN0$LG$EventLog");
    }
}
