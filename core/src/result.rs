use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::manifest::FieldType;
use crate::trigger::TriggerEvent;

/// One value in a result. Which fields exist, and their types, is declared by
/// the producing method's `output-schema`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
}

impl FieldValue {
    pub fn field_type(&self) -> FieldType {
        match self {
            FieldValue::Bool(_) => FieldType::Bool,
            FieldValue::Integer(_) => FieldType::Integer,
            FieldValue::Float(_) => FieldType::Float,
            FieldValue::String(_) => FieldType::String,
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Bool(value) => write!(f, "{value}"),
            FieldValue::Integer(value) => write!(f, "{value}"),
            FieldValue::Float(value) => write!(f, "{value}"),
            FieldValue::String(value) => f.write_str(value),
        }
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        FieldValue::Bool(value)
    }
}

impl From<i64> for FieldValue {
    fn from(value: i64) -> Self {
        FieldValue::Integer(value)
    }
}

impl From<f64> for FieldValue {
    fn from(value: f64) -> Self {
        FieldValue::Float(value)
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        FieldValue::String(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        FieldValue::String(value.to_string())
    }
}

/// What one method reports for one trigger: field name to value.
pub type Fields = BTreeMap<String, FieldValue>;

/// One entry in a session's append-only result list.
///
/// Never edited once appended, and never merged with another method's entry
/// at storage time: when two methods disagree, both entries stand, and
/// reconciling them is a consumer's job (fusion, the inference watcher).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultEntry {
    /// Producing method's manifest `name`.
    pub method: String,
    /// The event that fired it.
    pub trigger: TriggerEvent,
    /// Capture time of the packet that fired it, or the session's last packet
    /// for a session event — packet time rather than wall-clock, so a replayed
    /// capture produces the same results every run.
    pub timestamp: SystemTime,
    pub fields: Fields,
}
