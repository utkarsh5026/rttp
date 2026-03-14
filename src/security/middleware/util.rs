//! Shared utilities for security middleware.
//!
//! Private to this module tree — not part of the public API.

use crate::context::Context;

/// Extract the client IP from `X-Forwarded-For` (leftmost entry) or
/// `X-Real-IP`, falling back to `"unknown"`.
pub(super) fn extract_client_ip(ctx: &Context) -> String {
    ctx.request()
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.split(',').next().map(str::trim).map(str::to_owned))
        .or_else(|| ctx.request().headers().get("x-real-ip").map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Constant-time byte-slice equality comparison.
///
/// Returns `false` immediately if lengths differ (length is not secret),
/// but always compares every byte when lengths match.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
