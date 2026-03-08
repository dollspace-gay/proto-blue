//! AT Protocol Lexicon schema system: types, registry, and validation.
//!
//! Provides the `Lexicons` registry for loading and querying lexicon
//! schema documents, and a validation engine for checking `LexValue`
//! instances against those schemas.

pub mod error;
pub mod lexicons;
pub mod types;
pub mod validation;

pub use error::{LexiconError, ValidationError, ValidationResult};
pub use lexicons::Lexicons;
pub use types::{
    LexArray, LexBlob, LexBoolean, LexBytes, LexCidLink, LexInteger, LexObject, LexRecord, LexRef,
    LexRefUnion, LexString, LexToken, LexUnknown, LexUserType, LexXrpcBody, LexXrpcError,
    LexXrpcParameters, LexXrpcProcedure, LexXrpcQuery, LexXrpcSubscription, LexiconDoc,
};
pub use validation::{validate_object, validate_record, validate_value};
