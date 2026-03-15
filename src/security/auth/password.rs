//! Password hashing and verification using Argon2id.
//!
//! This module provides:
//!
//! - [`hash_password`] — hash a plaintext password with Argon2id.
//! - [`verify_password`] — verify a plaintext password against a stored hash.
//! - [`PasswordError`] — errors produced during hashing or verification.
//!
//! Argon2id is the winner of the Password Hashing Competition and the current
//! best-practice algorithm for storing passwords. It combines resistance to
//! both GPU-based attacks (Argon2i memory-hardness) and side-channel attacks
//! (Argon2d data-dependent memory access).
//!
//! # Defaults
//!
//! | Parameter   | Value  | Notes                          |
//! |-------------|--------|--------------------------------|
//! | Memory      | 64 MiB | `m_cost = 65536` KiB           |
//! | Iterations  | 3      | `t_cost`                       |
//! | Parallelism | 4      | `p_cost`                       |
//! | Salt        | 16 B   | Random, unique per hash        |
//! | Output      | PHC string format (`$argon2id$...`) |
//!
//! # Quick Start
//!
//! ```rust
//! use rttp::security::auth::password::{hash_password, verify_password};
//!
//! let hash = hash_password("hunter2").unwrap();
//!
//! assert!(verify_password("hunter2", &hash).unwrap());
//! assert!(!verify_password("wrong", &hash).unwrap());
//! ```

use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString},
};
use rand_core::OsRng;
use thiserror::Error;

/// Errors produced by password hashing or verification.
#[derive(Debug, Error)]
pub enum PasswordError {
    /// The hashing operation failed (e.g. invalid parameters or OOM).
    #[error("failed to hash password: {0}")]
    HashFailed(String),

    /// The stored hash string is not a valid PHC-format Argon2 hash.
    #[error("invalid password hash: {0}")]
    InvalidHash(String),
}

/// Hash `plain` using Argon2id with secure defaults.
///
/// A fresh random 16-byte salt is generated for every call, so two hashes of
/// the same password will always differ. The returned string is in PHC format
/// (`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`) and is safe to store
/// directly in a database column.
///
/// # Errors
///
/// Returns [`PasswordError::HashFailed`] if the Argon2 operation fails.
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = default_argon2();

    argon2
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::HashFailed(e.to_string()))
}

/// Verify that `plain` matches the stored `hash`.
///
/// The comparison is performed in constant time to prevent timing attacks.
/// `hash` must be a PHC-format string as produced by [`hash_password`].
///
/// Returns `Ok(true)` on a match, `Ok(false)` on a mismatch.
///
/// # Errors
///
/// Returns [`PasswordError::InvalidHash`] if `hash` cannot be parsed as a
/// valid PHC Argon2 hash string.
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(|e| PasswordError::InvalidHash(e.to_string()))?;

    Ok(default_argon2()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

/// Build an [`Argon2`] instance with the project-standard parameters.
///
/// Using a shared constructor keeps parameters consistent across all call
/// sites and makes future tuning a one-line change.
fn default_argon2() -> Argon2<'static> {
    use argon2::{Algorithm, Params, Version};

    // 64 MiB memory, 3 iterations, 4-way parallelism — OWASP recommended minimums.
    let params = Params::new(
        65_536, // m_cost: KiB  (64 MiB)
        3,      // t_cost: iterations
        4,      // p_cost: parallelism
        None,   // output length — use Argon2 default (32 B)
    )
    .expect("hard-coded Argon2 params are always valid");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password("correct-horse-battery-staple", &hash).unwrap());
    }

    #[test]
    fn wrong_password_does_not_verify() {
        let hash = hash_password("secret").unwrap();
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let h1 = hash_password("password").unwrap();
        let h2 = hash_password("password").unwrap();
        assert_ne!(h1, h2);
        assert!(verify_password("password", &h1).unwrap());
        assert!(verify_password("password", &h2).unwrap());
    }

    #[test]
    fn empty_password_is_hashable() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("non-empty", &hash).unwrap());
    }

    #[test]
    fn invalid_hash_string_returns_error() {
        let result = verify_password("anything", "not-a-valid-phc-string");
        assert!(matches!(result, Err(PasswordError::InvalidHash(_))));
    }

    #[test]
    fn hash_output_is_phc_argon2id_format() {
        let hash = hash_password("test").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "expected PHC argon2id prefix, got: {hash}"
        );
    }
}
