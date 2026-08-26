//! hk-rpc — node RPC surface sketch (JSON-RPC 2.0; final transport decided at P1).
//! Design rule: agent-first — every method an MCP server / x402 facilitator needs,
//! nothing EVM-shaped. Namespaces:
//!
//!   hk_chainInfo, hk_submitTx, hk_getAccount(nonce = next leaf index),
//!   mandate_get / mandate_available / mandate_subtree,
//!   channel_get / channel_settleClaim,
//!   shield_* (P2: note scanning endpoints for view services)
//!
//! Only DTOs live here for now.

use hk_primitives::{Amount, MandateId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ChainInfo {
    pub chain_id: String, // "hashkinetics-devnet-1"
    pub height: u64,
    pub finalized: u64, // == height under BFT — kept explicit for client sanity
}

#[derive(Serialize, Deserialize)]
pub struct MandateAvailable {
    pub mandate: MandateId,
    pub at: Timestamp,
    pub available: Amount, // min over ancestor chain (hk-mandate::available)
}
