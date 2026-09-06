//! Shared selector grammar for benchmark and evidence tools only.

use std::env::{self, VarError};

// The tail evidence binary uses the fallible entry point.
#[allow(dead_code)]
pub fn selector_values(name: &str) -> Option<Vec<String>> {
    try_selector_values(name).unwrap_or_else(|error| panic!("{error}"))
}

pub fn try_selector_values(name: &str) -> Result<Option<Vec<String>>, String> {
    parse_selector(name, env::var(name))
}

fn parse_selector(
    name: &str,
    value: Result<String, VarError>,
) -> Result<Option<Vec<String>>, String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Ok(None),
        Err(VarError::NotUnicode(_)) => return Err(format!("{name} must contain Unicode text")),
    };
    let values = value
        .split(',')
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                Err(format!("{name} contains an empty value"))
            } else {
                Ok(value.to_owned())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.iter().any(|value| value == "all") {
        if values != ["all"] {
            return Err(format!("{name}=all cannot be combined with values"));
        }
        Ok(None)
    } else {
        Ok(Some(values))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn selectors_preserve_order_and_leave_domain_validation_to_callers() {
        use super::*;
        assert_eq!(
            parse_selector("TEST", Err(VarError::NotPresent)).unwrap(),
            None
        );
        assert_eq!(parse_selector("TEST", Ok(" all ".into())).unwrap(), None);
        assert_eq!(
            parse_selector("TEST", Ok("8, 1,8,unknown".into())).unwrap(),
            Some(vec!["8".into(), "1".into(), "8".into(), "unknown".into()])
        );
    }

    #[test]
    fn selectors_reject_empty_mixed_all_and_nonunicode_values() {
        use super::*;
        for value in ["", " ", ",1", "1,", "1, ,2"] {
            assert_eq!(
                parse_selector("TEST", Ok(value.into())).unwrap_err(),
                "TEST contains an empty value"
            );
        }
        for value in ["all,1", "1,all", "all,all"] {
            assert_eq!(
                parse_selector("TEST", Ok(value.into())).unwrap_err(),
                "TEST=all cannot be combined with values"
            );
        }
        assert_eq!(
            parse_selector("TEST", Err(VarError::NotUnicode("invalid".into()))).unwrap_err(),
            "TEST must contain Unicode text"
        );
    }
}
