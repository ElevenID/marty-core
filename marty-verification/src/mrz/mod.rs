//! Machine Readable Zone (MRZ) parsing and validation.
//!
//! Supports TD1, TD2, and TD3 (passport) formats per ICAO 9303.

pub mod checksum;
pub mod parser;

pub use checksum::{compute_check_digit, validate_check_digit};
pub use parser::{parse_mrz, Mrz, MrzFormat};
