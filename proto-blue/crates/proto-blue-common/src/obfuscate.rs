//! Redaction helpers for logging auth material without leaking it.
//!
//! Mirrors TS `@atproto/common/obfuscate.ts`. Used by PDS/appview-
//! style servers to log request headers safely. Byte-exact with the
//! TS output for the common cases (JWT → `sub`, Basic → `user:***`,
//! bearer ≥ 12 chars → first+last char with `***` in between).

use base64::Engine as _;

const BASE64_STANDARD: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);
const BASE64_URL: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Redact an email to `f***e@d***n` form.
///
/// ```
/// # use proto_blue_common::obfuscate::obfuscate_email;
/// assert_eq!(obfuscate_email("alice@example.com"), "a***e@e***m");
/// ```
pub fn obfuscate_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => format!("{}@{}", obfuscate_word(local), obfuscate_word(domain)),
        None => obfuscate_word(email),
    }
}

/// Redact any word by keeping the first + last character and
/// replacing the middle with `***`. Short inputs (< 2 chars) fall
/// back to `***`.
pub fn obfuscate_word(word: &str) -> String {
    let chars: Vec<char> = word.chars().collect();
    match chars.len() {
        0 => String::new(),
        1 => format!("{}***", chars[0]),
        _ => format!(
            "{}***{}",
            chars.first().unwrap(),
            chars.last().unwrap(),
        ),
    }
}

/// Redact a map of HTTP headers. Keys are compared case-insensitively;
/// `authorization` and `dpop` get special handling. All other headers
/// pass through unchanged.
pub fn obfuscate_headers(
    headers: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in headers {
        let lower = key.to_ascii_lowercase();
        let v = if lower == "authorization" {
            obfuscate_auth_header(value)
        } else if lower == "dpop" {
            obfuscate_jwt(value).unwrap_or_else(|| "Invalid".to_string())
        } else {
            value.clone()
        };
        out.insert(key.clone(), v);
    }
    out
}

/// Redact an `Authorization` header value.
///
/// Recognises `Bearer <jwt-or-opaque>`, `DPoP <jwt>`, and
/// `Basic <base64>`. Unknown auth schemes return `"Invalid"` so the
/// log line records that an auth header was present without leaking
/// it.
pub fn obfuscate_auth_header(auth_header: &str) -> String {
    let Some(space_idx) = auth_header.find(' ') else {
        return "Invalid".to_string();
    };
    let ty = &auth_header[..space_idx];
    let rest = &auth_header[space_idx + 1..];
    match ty.to_ascii_lowercase().as_str() {
        "bearer" | "dpop" => format!("{} {}", ty, obfuscate_bearer(rest)),
        "basic" => format!(
            "{} {}",
            ty,
            obfuscate_basic(rest).unwrap_or_else(|| "Invalid".to_string()),
        ),
        _ => "Invalid".to_string(),
    }
}

/// Redact an HTTP Basic `base64(user:pass)` value to `user:***`.
/// Returns `None` for invalid base64 or missing `:`.
pub fn obfuscate_basic(token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let bytes = BASE64_STANDARD.decode(token).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(&bytes).ok()?;
    let col = s.find(':')?;
    let username = &s[..col];
    Some(format!("{username}:***"))
}

/// Redact a bearer-style token: JWT by `sub`, otherwise by
/// [`obfuscate_token`].
pub fn obfuscate_bearer(token: &str) -> String {
    obfuscate_jwt(token).unwrap_or_else(|| obfuscate_token(token))
}

/// Redact an opaque bearer token. Long tokens (≥ 12 chars) get the
/// same first+last treatment as [`obfuscate_word`]; shorter ones
/// collapse to `***` (empty stays empty).
pub fn obfuscate_token(token: &str) -> String {
    if token.chars().count() >= 12 {
        obfuscate_word(token)
    } else if token.is_empty() {
        String::new()
    } else {
        "***".to_string()
    }
}

/// Redact a JWT by extracting its `sub` claim. Returns `None` if the
/// token isn't shaped like a JWT (three dot-separated parts: header,
/// payload, signature) or doesn't carry a string `sub`.
///
/// Matches TS's behaviour: an invalid JWT returns `None`; a valid
/// JWT without a `sub` falls through to `header.payload.obfuscated`.
pub fn obfuscate_jwt(token: &str) -> Option<String> {
    let first_dot = token.find('.')?;
    let rest = &token[first_dot + 1..];
    let second_dot_rel = rest.find('.')?;
    let second_dot = first_dot + 1 + second_dot_rel;

    // Reject JWS-with-signature-of-signature (four parts, e.g. chained).
    let after_second = &token[second_dot + 1..];
    if after_second.contains('.') {
        return None;
    }

    let payload_enc = &token[first_dot + 1..second_dot];
    // JWT payloads are base64url-encoded. Be tolerant of missing
    // padding (which JWT always strips).
    let payload_bytes = BASE64_URL
        .decode(payload_enc)
        .or_else(|_| BASE64_STANDARD.decode(payload_enc))
        .ok()?;
    let payload_json = std::str::from_utf8(&payload_bytes).ok()?;
    let payload: serde_json::Value = serde_json::from_str(payload_json).ok()?;

    if let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) {
        return Some(sub.to_string());
    }
    // Valid JWT but no `sub`: strip the signature, keep the header
    // and payload so the log still records which token was used.
    Some(format!("{}.obfuscated", &token[..second_dot]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_with_two_chars() {
        assert_eq!(obfuscate_word("ab"), "a***b");
    }

    #[test]
    fn word_long() {
        assert_eq!(obfuscate_word("alice"), "a***e");
    }

    #[test]
    fn word_single_char() {
        assert_eq!(obfuscate_word("a"), "a***");
    }

    #[test]
    fn word_empty() {
        assert_eq!(obfuscate_word(""), "");
    }

    #[test]
    fn email_standard() {
        assert_eq!(obfuscate_email("alice@example.com"), "a***e@e***m");
    }

    #[test]
    fn email_without_at() {
        assert_eq!(obfuscate_email("alice"), "a***e");
    }

    #[test]
    fn auth_bearer_long_token() {
        let out = obfuscate_auth_header("Bearer abcdefghijklmnop");
        assert_eq!(out, "Bearer a***p");
    }

    #[test]
    fn auth_bearer_short_token() {
        // token.len() < 12 collapses to "***"
        assert_eq!(obfuscate_auth_header("Bearer short"), "Bearer ***");
    }

    #[test]
    fn auth_basic_user_pass() {
        // base64("alice:secret") = YWxpY2U6c2VjcmV0
        let out = obfuscate_auth_header("Basic YWxpY2U6c2VjcmV0");
        assert_eq!(out, "Basic alice:***");
    }

    #[test]
    fn auth_basic_invalid() {
        let out = obfuscate_auth_header("Basic !!!not-base64!!!");
        assert_eq!(out, "Basic Invalid");
    }

    #[test]
    fn auth_unknown_scheme_is_invalid() {
        assert_eq!(obfuscate_auth_header("Digest xyz"), "Invalid");
    }

    #[test]
    fn auth_header_without_space_is_invalid() {
        assert_eq!(obfuscate_auth_header("bearer-no-space"), "Invalid");
    }

    #[test]
    fn jwt_with_sub_returns_sub() {
        // Header: {"alg":"HS256","typ":"JWT"} — ignored
        // Payload: {"sub":"did:plc:alice"}
        // base64url(payload) = eyJzdWIiOiJkaWQ6cGxjOmFsaWNlIn0
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFsaWNlIn0.ignoredsig";
        assert_eq!(obfuscate_jwt(jwt).as_deref(), Some("did:plc:alice"));
    }

    #[test]
    fn jwt_without_sub_returns_obfuscated_suffix() {
        // Payload: {"foo":"bar"} = eyJmb28iOiJiYXIifQ
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig";
        let out = obfuscate_jwt(jwt).unwrap();
        assert_eq!(out, "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.obfuscated");
    }

    #[test]
    fn jwt_malformed_returns_none() {
        assert!(obfuscate_jwt("not.a.jwt.has.too.many.dots").is_none());
        assert!(obfuscate_jwt("onlyonepart").is_none());
        assert!(obfuscate_jwt("two.parts").is_none());
    }

    #[test]
    fn bearer_falls_back_to_token_obfuscation_for_opaque() {
        // Not JWT-shaped (one dot, not two) — falls to obfuscate_token.
        assert_eq!(obfuscate_bearer("abcdefghijklmnop"), "a***p");
    }

    #[test]
    fn headers_redacts_auth_and_dpop_only() {
        let mut h = std::collections::BTreeMap::new();
        h.insert("Authorization".to_string(), "Bearer abcdefghijklmnop".to_string());
        h.insert("Content-Type".to_string(), "application/json".to_string());
        h.insert("X-Custom".to_string(), "hello".to_string());

        let out = obfuscate_headers(&h);
        assert_eq!(out["Authorization"], "Bearer a***p");
        assert_eq!(out["Content-Type"], "application/json");
        assert_eq!(out["X-Custom"], "hello");
    }
}
