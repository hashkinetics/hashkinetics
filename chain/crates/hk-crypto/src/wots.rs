//! WOTS+ — B-channel balance signing (plan §6). SPEC NOTES ONLY — deliberately not
//! implemented yet: WOTS+ has subtle checksum/ADRS details and we will NOT ship
//! hand-rolled signature code without KATs. Implementation path:
//!   1. Port from the XMSS reference implementation (wots.c) with its test vectors.
//!   2. Cross-check against a FIPS 205 reference (SLH-DSA's internal WOTS+ differs
//!      in ADRS layout — do NOT mix; ours follows RFC 8391 §3 for standalone use).
//!
//! Parameters (target): n=24 or 32, w=16 → len = len_1 + len_2 chains.
//! Sig ≈ len·n bytes (~0.75–1.5 KB) — µs sign/verify, per-payment inside B-channels.

/// Parameter set placeholder (RFC 8391 §3.1.1 naming).
#[derive(Clone, Copy, Debug)]
pub struct WotsParams {
    /// Security parameter in bytes (24 → 192-bit class, matches n=24 stack of plan §3.2).
    pub n: usize,
    /// Winternitz parameter.
    pub w: usize,
}

pub const WOTS_N24_W16: WotsParams = WotsParams { n: 24, w: 16 };

// TODO(P1): keygen/sign/verify against xmss-reference KATs. Tracked in chain/README.md order-of-work.
