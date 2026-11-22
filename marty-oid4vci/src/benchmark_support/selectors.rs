//! Shared selector grammar for benchmark and evidence tools only.

use std::env::{self, VarError};

fn try_selector_values(name: &str) -> Result<Option<Vec<String>>, String> {
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

#[derive(Debug)]
pub struct SelectorError {
    name: String,
    reason: Reason,
}

#[derive(Debug)]
enum Reason {
    Grammar(String),
    Unsupported { value: String, allowed: String },
    NotInteger(String),
    NonCanonical { value: String, canonical: String },
    Duplicate(String),
}

impl SelectorError {
    fn new(name: &str, reason: Reason) -> Self {
        Self {
            name: name.to_owned(),
            reason,
        }
    }

    fn message(&self, include_value: bool) -> String {
        let name = &self.name;
        let field = |value: &str| {
            if include_value {
                format!("{name} value '{value}'")
            } else {
                format!("{name} value")
            }
        };
        match &self.reason {
            Reason::Grammar(message) => message.clone(),
            Reason::Unsupported { value, allowed } => {
                format!("unsupported {}; expected one of {allowed}", field(value))
            }
            Reason::NotInteger(value) => format!("{} is not an integer", field(value)),
            Reason::NonCanonical { value, .. } => format!("{} is not canonical", field(value)),
            Reason::Duplicate(value) => format!("{name} repeats '{value}'"),
        }
    }

    // Panic-based harnesses historically report both sides of this assertion.
    #[allow(dead_code)] // The tail evidence binary returns its diagnostics.
    pub fn panic_with_value<T>(self, include_value: bool) -> T {
        let message = self.message(include_value);
        if let Reason::NonCanonical { canonical, value } = self.reason {
            assert_eq!(canonical, value, "{message}");
        }
        panic!("{message}")
    }
}

impl From<SelectorError> for String {
    fn from(error: SelectorError) -> Self {
        error.message(true)
    }
}

fn select_values<T: Copy + Eq>(
    name: &str,
    allowed: &[T],
    label: impl Fn(T) -> String,
    parse: impl Fn(&str) -> Result<T, Reason>,
) -> Result<Vec<T>, SelectorError> {
    let values = try_selector_values(name)
        .map_err(|message| SelectorError::new(name, Reason::Grammar(message)))?;
    let Some(values) = values else {
        return Ok(allowed.to_vec());
    };
    let selected = values
        .iter()
        .map(|value| parse(value).map_err(|reason| SelectorError::new(name, reason)))
        .collect::<Result<Vec<_>, _>>()?;
    // Domain errors take precedence over duplicates, as in all five harnesses.
    for (index, &value) in selected.iter().enumerate() {
        if selected[..index].contains(&value) {
            return Err(SelectorError::new(name, Reason::Duplicate(label(value))));
        }
    }
    Ok(selected)
}

pub fn parse_named_selector<T: Copy + Eq>(
    name: &str,
    allowed: &[T],
    label: impl Fn(T) -> &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, SelectorError> {
    select_values(
        name,
        allowed,
        |value| label(value).to_owned(),
        |value| {
            parse(value).ok_or_else(|| Reason::Unsupported {
                value: value.to_owned(),
                allowed: allowed
                    .iter()
                    .copied()
                    .map(&label)
                    .collect::<Vec<_>>()
                    .join(","),
            })
        },
    )
}

pub fn parse_numeric_selector(name: &str, allowed: &[usize]) -> Result<Vec<usize>, SelectorError> {
    select_values(
        name,
        allowed,
        |n| n.to_string(),
        |value| {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| Reason::NotInteger(value.to_owned()))?;
            let canonical = parsed.to_string();
            if canonical != value {
                return Err(Reason::NonCanonical {
                    value: value.to_owned(),
                    canonical,
                });
            }
            if !allowed.contains(&parsed) {
                return Err(Reason::Unsupported {
                    value: value.to_owned(),
                    allowed: allowed
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                });
            }
            Ok(parsed)
        },
    )
}

#[cfg(test)]
mod tests {

    #[test]
    fn domain_errors_preserve_precedence_and_harness_diagnostics() {
        use super::*;
        // This variable is private to this test within each test binary.
        let name = "MARTY_TEST_DOMAIN_SELECTOR";
        let parse = || parse_numeric_selector(name, &[1, 8]);
        std::env::set_var(name, "1,1,bad");
        let error = parse().unwrap_err();
        assert_eq!(
            error.message(false),
            format!("{name} value is not an integer")
        );
        assert_eq!(
            String::from(error),
            format!("{name} value 'bad' is not an integer")
        );
        std::env::set_var(name, "01");
        assert_eq!(
            String::from(parse().unwrap_err()),
            format!("{name} value '01' is not canonical")
        );
        std::env::set_var(name, "1,1");
        assert_eq!(
            String::from(parse().unwrap_err()),
            format!("{name} repeats '1'")
        );
        std::env::set_var(name, "8,1");
        assert_eq!(parse().unwrap(), [8, 1]);
        std::env::set_var(name, "unknown");
        let error = parse_named_selector(name, &["first"], |s| s, |_| None).unwrap_err();
        assert_eq!(
            error.message(false),
            format!("unsupported {name} value; expected one of first")
        );
        std::env::remove_var(name);
    }

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
