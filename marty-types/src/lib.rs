//! Shared type definitions and constants for the Marty ecosystem
//!
//! This crate provides centralized type definitions, constants, and error codes
//! used across Marty components. It includes:
//!
//! - ISO 18013-5 mDL namespaces and document types
//! - W3C Verifiable Credentials contexts
//! - Credential format identifiers
//! - Hierarchical error codes
//!
//! ## Features
//!
//! - `python`: Enable PyO3 bindings for Python integration
//!
//! ## Generated Code
//!
//! Most of this crate's content is generated from YAML schemas in the `schema/` directory.
//! To regenerate, run: `python codegen/generate.py`

#[cfg(feature = "python")]
use pyo3::prelude::*;

pub mod generated;
pub mod open_badges;

// Re-export commonly used items
pub use generated::{error_codes, namespaces};

#[cfg(feature = "python")]
#[pymodule]
fn marty_types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    generated::namespaces::register_namespace_module(m)?;
    generated::error_codes::register_error_code_module(m)?;
    Ok(())
}
