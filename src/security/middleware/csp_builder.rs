//! Typed Content Security Policy builder.
//!
//! Constructs CSP header values from structured directives so you never have
//! to hand-write `"default-src 'self'; script-src 'self' https://cdn.example.com"`
//! yourself. Supports nonces for inline scripts/styles.
//!
//! # Examples
//!
//! ```rust
//! use rttp::security::middleware::csp_builder::CspBuilder;
//!
//! let csp = CspBuilder::new()
//!     .default_src(&["'self'"])
//!     .script_src(&["'self'", "https://cdn.example.com"])
//!     .style_src(&["'self'", "'unsafe-inline'"])
//!     .img_src(&["'self'", "data:"])
//!     .connect_src(&["'self'", "https://api.example.com"])
//!     .build();
//!
//! assert!(csp.contains("default-src 'self'"));
//! assert!(csp.contains("script-src 'self' https://cdn.example.com"));
//! ```

use std::collections::BTreeMap;

/// A typed builder for Content Security Policy header values.
///
/// Each directive is stored independently and serialized in a deterministic
/// order. The builder accepts raw source strings so you can use any valid CSP
/// source expression (`'self'`, `'unsafe-inline'`, `'nonce-...'`, URLs, etc.).
#[derive(Debug, Clone, Default)]
pub struct CspBuilder {
    directives: BTreeMap<String, Vec<String>>,
}

impl CspBuilder {
    /// Create an empty CSP builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a raw directive with the given sources.
    ///
    /// This is the escape hatch for directives not covered by the typed methods.
    #[must_use]
    pub fn directive(mut self, name: &str, sources: &[&str]) -> Self {
        self.directives.insert(
            name.to_owned(),
            sources.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// Set `default-src` directive.
    #[must_use]
    pub fn default_src(self, sources: &[&str]) -> Self {
        self.directive("default-src", sources)
    }

    /// Set `script-src` directive.
    #[must_use]
    pub fn script_src(self, sources: &[&str]) -> Self {
        self.directive("script-src", sources)
    }

    /// Set `style-src` directive.
    #[must_use]
    pub fn style_src(self, sources: &[&str]) -> Self {
        self.directive("style-src", sources)
    }

    /// Set `img-src` directive.
    #[must_use]
    pub fn img_src(self, sources: &[&str]) -> Self {
        self.directive("img-src", sources)
    }

    /// Set `font-src` directive.
    #[must_use]
    pub fn font_src(self, sources: &[&str]) -> Self {
        self.directive("font-src", sources)
    }

    /// Set `connect-src` directive.
    #[must_use]
    pub fn connect_src(self, sources: &[&str]) -> Self {
        self.directive("connect-src", sources)
    }

    /// Set `media-src` directive.
    #[must_use]
    pub fn media_src(self, sources: &[&str]) -> Self {
        self.directive("media-src", sources)
    }

    /// Set `object-src` directive.
    #[must_use]
    pub fn object_src(self, sources: &[&str]) -> Self {
        self.directive("object-src", sources)
    }

    /// Set `frame-src` directive.
    #[must_use]
    pub fn frame_src(self, sources: &[&str]) -> Self {
        self.directive("frame-src", sources)
    }

    /// Set `child-src` directive.
    #[must_use]
    pub fn child_src(self, sources: &[&str]) -> Self {
        self.directive("child-src", sources)
    }

    /// Set `worker-src` directive.
    #[must_use]
    pub fn worker_src(self, sources: &[&str]) -> Self {
        self.directive("worker-src", sources)
    }

    /// Set `form-action` directive.
    #[must_use]
    pub fn form_action(self, sources: &[&str]) -> Self {
        self.directive("form-action", sources)
    }

    /// Set `frame-ancestors` directive.
    #[must_use]
    pub fn frame_ancestors(self, sources: &[&str]) -> Self {
        self.directive("frame-ancestors", sources)
    }

    /// Set `base-uri` directive.
    #[must_use]
    pub fn base_uri(self, sources: &[&str]) -> Self {
        self.directive("base-uri", sources)
    }

    /// Set `report-uri` directive.
    #[must_use]
    pub fn report_uri(self, uri: &str) -> Self {
        self.directive("report-uri", &[uri])
    }

    /// Set `report-to` directive.
    #[must_use]
    pub fn report_to(self, group: &str) -> Self {
        self.directive("report-to", &[group])
    }

    /// Add `upgrade-insecure-requests` directive.
    #[must_use]
    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives
            .insert("upgrade-insecure-requests".to_owned(), vec![]);
        self
    }

    /// Add `block-all-mixed-content` directive.
    #[must_use]
    pub fn block_all_mixed_content(mut self) -> Self {
        self.directives
            .insert("block-all-mixed-content".to_owned(), vec![]);
        self
    }

    /// Generate a nonce value and return a `'nonce-<base64>'` source expression.
    ///
    /// The caller should embed the raw nonce (without the CSP wrapper) in the
    /// HTML `<script nonce="...">` or `<style nonce="...">` attribute.
    pub fn generate_nonce() -> (String, String) {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).expect("failed to generate random nonce");
        let nonce = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, buf);
        let csp_source = format!("'nonce-{nonce}'");
        (nonce, csp_source)
    }

    /// Build the CSP header value string.
    ///
    /// Directives are sorted alphabetically for deterministic output.
    #[must_use]
    pub fn build(&self) -> String {
        self.directives
            .iter()
            .map(|(name, sources)| {
                if sources.is_empty() {
                    name.clone()
                } else {
                    format!("{name} {}", sources.join(" "))
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl From<CspBuilder> for String {
    fn from(builder: CspBuilder) -> Self {
        builder.build()
    }
}
