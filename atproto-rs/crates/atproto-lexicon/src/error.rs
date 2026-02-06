//! Error types for the lexicon system.

use thiserror::Error;

/// Errors that can occur when working with lexicons.
#[derive(Debug, Error)]
pub enum LexiconError {
    #[error("Invalid lexicon document: {0}")]
    InvalidDocument(String),
    #[error("Duplicate lexicon: {0}")]
    DuplicateLexicon(String),
    #[error("Lexicon not found: {0}")]
    NotFound(String),
    #[error("Definition not found: {0}")]
    DefNotFound(String),
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Errors that occur during validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{path}: {message}")]
    InvalidValue { path: String, message: String },
    #[error("Lexicon not found: {0}")]
    LexiconNotFound(String),
    #[error("Definition not found: {0}")]
    DefNotFound(String),
}

impl ValidationError {
    pub fn new(path: &str, message: impl Into<String>) -> Self {
        ValidationError::InvalidValue {
            path: path.to_string(),
            message: message.into(),
        }
    }
}

/// Result of validation: either the (possibly modified) value or an error.
pub type ValidationResult = Result<(), ValidationError>;
