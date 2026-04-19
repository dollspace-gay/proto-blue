//! Error types for the lexicon system.

use thiserror::Error;

/// Errors that can occur when working with lexicons.
#[derive(Debug, Error)]
pub enum LexiconError {
    #[error("Invalid lexicon document: {0}")]
    InvalidDocument(String),
    #[error("Invalid lexicon schema: {0}")]
    InvalidSchema(String),
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- ValidationError::new() ---

    #[test]
    fn validation_error_new_creates_invalid_value() {
        let err = ValidationError::new("$.foo.bar", "expected string");
        match &err {
            ValidationError::InvalidValue { path, message } => {
                assert_eq!(path, "$.foo.bar");
                assert_eq!(message, "expected string");
            }
            _ => panic!("Expected InvalidValue variant"),
        }
    }

    #[test]
    fn validation_error_new_accepts_string_message() {
        let err = ValidationError::new("/root", String::from("bad value"));
        match &err {
            ValidationError::InvalidValue { path, message } => {
                assert_eq!(path, "/root");
                assert_eq!(message, "bad value");
            }
            _ => panic!("Expected InvalidValue variant"),
        }
    }

    // --- ValidationError Display formatting ---

    #[test]
    fn display_invalid_value() {
        let err = ValidationError::new("$.text", "too long");
        assert_eq!(format!("{err}"), "$.text: too long");
    }

    #[test]
    fn display_lexicon_not_found() {
        let err = ValidationError::LexiconNotFound("com.example.missing".to_string());
        assert_eq!(format!("{err}"), "Lexicon not found: com.example.missing");
    }

    #[test]
    fn display_def_not_found() {
        let err = ValidationError::DefNotFound("com.example.thing#widget".to_string());
        assert_eq!(
            format!("{err}"),
            "Definition not found: com.example.thing#widget"
        );
    }

    // --- LexiconError Display formatting ---

    #[test]
    fn display_invalid_document() {
        let err = LexiconError::InvalidDocument("missing id field".to_string());
        assert_eq!(
            format!("{err}"),
            "Invalid lexicon document: missing id field"
        );
    }

    #[test]
    fn display_duplicate_lexicon() {
        let err = LexiconError::DuplicateLexicon("com.example.dupe".to_string());
        assert_eq!(format!("{err}"), "Duplicate lexicon: com.example.dupe");
    }

    #[test]
    fn display_not_found() {
        let err = LexiconError::NotFound("com.example.gone".to_string());
        assert_eq!(format!("{err}"), "Lexicon not found: com.example.gone");
    }

    #[test]
    fn display_def_not_found_lexicon_error() {
        let err = LexiconError::DefNotFound("com.example.thing#missing".to_string());
        assert_eq!(
            format!("{err}"),
            "Definition not found: com.example.thing#missing"
        );
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let expected_msg = format!("JSON parse error: {json_err}");
        let err = LexiconError::JsonError(json_err);
        assert_eq!(format!("{err}"), expected_msg);
    }

    #[test]
    fn json_error_from_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let lexicon_err: LexiconError = json_err.into();
        let display = format!("{lexicon_err}");
        assert!(display.starts_with("JSON parse error:"));
    }
}
