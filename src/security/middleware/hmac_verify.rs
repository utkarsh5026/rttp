//! HMAC request body signature verification middleware.
//!
//! Validates webhook-style signatures where the sender computes
//! `HMAC-SHA256(secret, body)` and sends it in a request header. This is the
//! pattern used by GitHub (`X-Hub-Signature-256`), Stripe, Slack, and many
//! other webhook providers.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::middleware::HmacVerifyMiddleware;
//! use rttp::middleware::from_middleware;
//!
//! let mw = from_middleware(Arc::new(
//!     HmacVerifyMiddleware::new(b"whsec_my_webhook_secret")
//!         .header("X-Hub-Signature-256")
//!         .prefix("sha256="),
//! ));
//! ```

use std::{future::Future, pin::Pin, sync::Arc};

use tracing::warn;

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
    security::middleware::util::constant_time_eq,
};

/// HMAC-SHA256 request body signature verification middleware.
///
/// Reads the signature from a configurable request header, computes
/// `HMAC-SHA256(secret, body)`, and compares using constant-time equality.
/// Requests with missing or invalid signatures are rejected with
/// `403 Forbidden`.
pub struct HmacVerifyMiddleware {
    secret: Arc<Vec<u8>>,
    /// Header name to read the signature from.
    header_name: String,
    /// Optional prefix to strip from the header value (e.g. `"sha256="`).
    prefix: String,
}

impl HmacVerifyMiddleware {
    /// Create a new middleware with the given HMAC secret.
    ///
    /// Defaults to reading the signature from `X-Signature-256` with a
    /// `sha256=` prefix.
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: Arc::new(secret.to_vec()),
            header_name: "X-Signature-256".to_owned(),
            prefix: "sha256=".to_owned(),
        }
    }

    /// Set the header name to read the signature from.
    #[must_use]
    pub fn header(mut self, name: &str) -> Self {
        self.header_name = name.to_owned();
        self
    }

    /// Set the prefix to strip from the header value before hex-decoding.
    ///
    /// Pass an empty string if no prefix is used.
    #[must_use]
    pub fn prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_owned();
        self
    }
}

/// Compute HMAC-SHA256(key, message) and return hex-encoded digest.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    // Pad or hash the key to block size.
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        key_block[..HASH_SIZE].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Inner padding
    let mut i_key_pad = [0x36u8; BLOCK_SIZE];
    for (i, b) in key_block.iter().enumerate() {
        i_key_pad[i] ^= b;
    }

    // Outer padding
    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    for (i, b) in key_block.iter().enumerate() {
        o_key_pad[i] ^= b;
    }

    // Inner hash: SHA256(i_key_pad || message)
    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    // Outer hash: SHA256(o_key_pad || inner_hash)
    let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer).to_vec()
}

/// Minimal SHA-256 implementation (no external crate needed).
fn sha256(data: &[u8]) -> [u8; 32] {
    use std::num::Wrapping as W;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [W<u32>; 8] = [
        W(0x6a09e667),
        W(0xbb67ae85),
        W(0x3c6ef372),
        W(0xa54ff53a),
        W(0x510e527f),
        W(0x9b05688c),
        W(0x1f83d9ab),
        W(0x5be0cd19),
    ];

    // Pre-processing: padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in padded.chunks_exact(64) {
        let mut w = [W(0u32); 64];
        for i in 0..16 {
            w[i] = W(u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]));
        }
        for i in 16..64 {
            let s0 = ror32(w[i - 15].0, 7) ^ ror32(w[i - 15].0, 18) ^ (w[i - 15].0 >> 3);
            let s1 = ror32(w[i - 2].0, 17) ^ ror32(w[i - 2].0, 19) ^ (w[i - 2].0 >> 10);
            w[i] = w[i - 16] + W(s0) + w[i - 7] + W(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = W(ror32(e.0, 6) ^ ror32(e.0, 11) ^ ror32(e.0, 25));
            let ch = W((e.0 & f.0) ^ ((!e.0) & g.0));
            let temp1 = hh + s1 + ch + W(K[i]) + w[i];
            let s0 = W(ror32(a.0, 2) ^ ror32(a.0, 13) ^ ror32(a.0, 22));
            let maj = W((a.0 & b.0) ^ (a.0 & c.0) ^ (b.0 & c.0));
            let temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[4 * i..4 * i + 4].copy_from_slice(&val.0.to_be_bytes());
    }
    result
}

fn ror32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}


/// Decode a hex string into bytes.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

impl Middleware for HmacVerifyMiddleware {
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let secret = Arc::clone(&self.secret);
        let header_name = self.header_name.clone();
        let prefix = self.prefix.clone();

        Box::pin(async move {
            // Read signature header.
            let sig_header = ctx
                .request()
                .headers()
                .get(&header_name.to_ascii_lowercase())
                .map(str::to_owned);

            let Some(sig_value) = sig_header else {
                warn!(header = %header_name, "HMAC signature header missing");
                return Response::new(StatusCode::Forbidden).body("Missing signature header");
            };

            // Strip prefix.
            let hex_sig = if !prefix.is_empty() {
                match sig_value.strip_prefix(&prefix) {
                    Some(s) => s,
                    None => {
                        warn!("HMAC signature missing expected prefix");
                        return Response::new(StatusCode::Forbidden)
                            .body("Invalid signature format");
                    }
                }
            } else {
                &sig_value
            };

            // Decode hex signature.
            let Some(received_sig) = hex_decode(hex_sig) else {
                warn!("HMAC signature is not valid hex");
                return Response::new(StatusCode::Forbidden).body("Invalid signature format");
            };

            // Compute expected HMAC.
            let body = ctx.request().body();
            let expected_sig = hmac_sha256(&secret, body);

            if !constant_time_eq(&received_sig, &expected_sig) {
                warn!("HMAC signature mismatch");
                return Response::new(StatusCode::Forbidden).body("Invalid signature");
            }

            next.run(ctx).await
        })
    }
}
