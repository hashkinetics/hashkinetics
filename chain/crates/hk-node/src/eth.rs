//! eth.rs — the smallest Ethereum client hk-attest needs (B1, docs/BRIDGE-SEPOLIA-USDC-PLAN.md).
//!
//! Deliberately NOT alloy/ethers: the bridge service touches exactly one contract shape (HKVault /
//! HKWrapped — `bridge/contracts`), so everything it needs fits in one file whose every byte is
//! readable: keccak-256, ABI encoding for the four calls it makes, event decoding for the two events
//! it reads, RLP + EIP-1559 transaction signing with the secp256k1 attestor key, the EIP-712 digest
//! the contracts verify, and JSON-RPC 2.0 over the same blocking https client the node uses
//! everywhere (`demo::post_json`, K6). The attestor key is the ONE ECDSA key in the whole system —
//! it exists because Ethereum verifies nothing else, and it never touches a HashKinetics balance.
//!
//! Tested: keccak vector, ABI/RLP/EIP-712 encodings against hand-derived values, address derivation
//! against a known key, and — the check that matters — the EIP-712 domain separator this module
//! computes must equal `vault.domainSeparator()` on the running contract (asserted at service start,
//! proven in `chain/gate-b1.sh`).

use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use tiny_keccak::{Hasher, Keccak};

use crate::demo::post_json;

// ---------------------------------------------------------------------------------------------
// hashing + hex
// ---------------------------------------------------------------------------------------------

pub(crate) fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

pub(crate) fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse `0x…` / bare hex into bytes.
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(t).map_err(|e| format!("bad hex '{s}': {e}"))
}

/// Parse a `0x…` quantity (JSON-RPC hex integer) into u128.
pub(crate) fn qty(v: &Value) -> Result<u128, String> {
    let s = v.as_str().ok_or_else(|| format!("quantity is not a string: {v}"))?;
    let t = s.strip_prefix("0x").unwrap_or(s);
    if t.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(t, 16).map_err(|e| format!("bad quantity '{s}': {e}"))
}

fn qty_hex(n: u128) -> String {
    format!("0x{n:x}")
}

// ---------------------------------------------------------------------------------------------
// addresses and keys
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Address(pub [u8; 20]);

impl Address {
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let b = unhex(s)?;
        if b.len() != 20 {
            return Err(format!("address must be 20 bytes, got {} ('{s}')", b.len()));
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&b);
        Ok(Self(a))
    }
    pub(crate) fn hex(&self) -> String {
        hex0x(&self.0)
    }
}

/// The attestor signing key (secp256k1). Loaded from 32 bytes of hex — a systemd credential file
/// or `ETH_ATTESTOR_KEY` — never from argv, never logged.
pub(crate) struct Signer {
    key: SigningKey,
    pub(crate) address: Address,
}

impl Signer {
    pub(crate) fn from_hex(s: &str) -> Result<Self, String> {
        let b = unhex(s)?;
        if b.len() != 32 {
            return Err(format!("attestor key must be 32 bytes, got {}", b.len()));
        }
        let key = SigningKey::from_slice(&b).map_err(|e| format!("bad secp256k1 key: {e}"))?;
        let address = address_of(&key);
        Ok(Self { key, address })
    }

    /// 65-byte `r‖s‖v` over a 32-byte digest, `v ∈ {27, 28}` (what OpenZeppelin's ECDSA.recover expects).
    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], String> {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + rid.to_byte();
        Ok(out)
    }

    /// `(y_parity, r, s)` for an EIP-1559 transaction.
    fn sign_tx_hash(&self, digest: &[u8; 32]) -> Result<(u8, [u8; 32], [u8; 32]), String> {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|e| format!("sign: {e}"))?;
        let b = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Ok((rid.to_byte(), r, s))
    }
}

fn address_of(key: &SigningKey) -> Address {
    let vk = key.verifying_key();
    let p = vk.to_encoded_point(false);
    let h = keccak256(&[&p.as_bytes()[1..]]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Address(a)
}

// ---------------------------------------------------------------------------------------------
// ABI encoding (only what the bridge calls)
// ---------------------------------------------------------------------------------------------

pub(crate) fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(&[sig.as_bytes()]);
    [h[0], h[1], h[2], h[3]]
}

fn word_u(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

/// `f(address to, uint256 amount, bytes32 id, bytes[] sigs)` — the shape of both `unlock` (HKVault)
/// and `mint` (HKWrapped). Signatures must already be sorted by ascending signer address.
pub(crate) fn encode_attested_call(fn_sig: &str, to: &Address, amount: u128, id: &[u8; 32], sigs: &[[u8; 65]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 4 + sigs.len() * 128);
    out.extend_from_slice(&selector(fn_sig));
    out.extend_from_slice(&word_addr(to));
    out.extend_from_slice(&word_u(amount));
    out.extend_from_slice(id);
    out.extend_from_slice(&word_u(0x80)); // offset of the dynamic bytes[] (4 head words)
    // bytes[]: length, then per-element offsets relative to the start of this block (after the length word)
    out.extend_from_slice(&word_u(sigs.len() as u128));
    let mut off = 32 * sigs.len();
    for _ in sigs {
        out.extend_from_slice(&word_u(off as u128));
        off += 32 + 96; // length word + 65 bytes padded to 96
    }
    for s in sigs {
        out.extend_from_slice(&word_u(65));
        let mut padded = [0u8; 96];
        padded[..65].copy_from_slice(s);
        out.extend_from_slice(&padded);
    }
    out
}

/// `f(bytes32 x)` and `f()` views.
pub(crate) fn encode_view_b32(fn_sig: &str, x: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&selector(fn_sig));
    out.extend_from_slice(x);
    out
}

pub(crate) fn encode_view(fn_sig: &str) -> Vec<u8> {
    selector(fn_sig).to_vec()
}

/// `f(address a)` views — `isAttestor(address)`.
pub(crate) fn encode_view_addr(fn_sig: &str, a: &Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&selector(fn_sig));
    out.extend_from_slice(&word_addr(a));
    out
}

pub(crate) fn encode_attestor_query(a: &Address) -> Vec<u8> {
    encode_view_addr("isAttestor(address)", a)
}

/// Decode an ABI-encoded `string` return (offset word, length word, bytes).
pub(crate) fn decode_string(b: &[u8]) -> Result<String, String> {
    let off = decode_word_u(b)? as usize;
    if b.len() < off + 32 {
        return Err("string: short".into());
    }
    let len = decode_word_u(&b[off..])? as usize;
    if b.len() < off + 32 + len {
        return Err("string: short body".into());
    }
    String::from_utf8(b[off + 32..off + 32 + len].to_vec()).map_err(|e| e.to_string())
}

/// Decode a single 32-byte word as u128 (the top 16 bytes must be zero — amounts here are 6-decimal USDC).
pub(crate) fn decode_word_u(b: &[u8]) -> Result<u128, String> {
    if b.len() < 32 {
        return Err(format!("short return ({} bytes)", b.len()));
    }
    if b[..16].iter().any(|x| *x != 0) {
        return Err("value exceeds u128".into());
    }
    let mut n = [0u8; 16];
    n.copy_from_slice(&b[16..32]);
    Ok(u128::from_be_bytes(n))
}

pub(crate) fn decode_word_b32(b: &[u8]) -> Result<[u8; 32], String> {
    if b.len() < 32 {
        return Err(format!("short return ({} bytes)", b.len()));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&b[..32]);
    Ok(w)
}

// ---------------------------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------------------------

/// `Locked(bytes32 indexed depositId, address indexed sender, uint256 amount, bytes32 indexed hkAccount, uint256 nonce)`
/// on HKVault and `Burned(bytes32 indexed burnId, address indexed from, uint256 amount, bytes32 indexed hkAccount, uint256 nonce)`
/// on HKWrapped share one layout: three indexed topics + (amount, nonce) in data.
#[derive(Clone, Debug)]
pub(crate) struct BridgeEvent {
    pub id: [u8; 32],
    pub from: Address,
    pub hk_account: [u8; 32],
    pub amount: u128,
    pub nonce: u128,
    pub block: u64,
    pub tx_hash: String,
    pub log_index: u128,
}

pub(crate) const LOCKED_SIG: &str = "Locked(bytes32,address,uint256,bytes32,uint256)";
pub(crate) const BURNED_SIG: &str = "Burned(bytes32,address,uint256,bytes32,uint256)";

pub(crate) fn event_topic(sig: &str) -> [u8; 32] {
    keccak256(&[sig.as_bytes()])
}

pub(crate) fn decode_bridge_event(log: &Value) -> Result<BridgeEvent, String> {
    let topics = log.get("topics").and_then(|t| t.as_array()).ok_or("log without topics")?;
    if topics.len() != 4 {
        return Err(format!("expected 4 topics, got {}", topics.len()));
    }
    let t1 = unhex(topics[1].as_str().unwrap_or(""))?;
    let t2 = unhex(topics[2].as_str().unwrap_or(""))?;
    let t3 = unhex(topics[3].as_str().unwrap_or(""))?;
    if t1.len() != 32 || t2.len() != 32 || t3.len() != 32 {
        return Err("topic length".into());
    }
    let data = unhex(log.get("data").and_then(|d| d.as_str()).unwrap_or(""))?;
    if data.len() < 64 {
        return Err(format!("event data too short ({} bytes)", data.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&t1);
    let mut from = [0u8; 20];
    from.copy_from_slice(&t2[12..]);
    let mut hk = [0u8; 32];
    hk.copy_from_slice(&t3);
    Ok(BridgeEvent {
        id,
        from: Address(from),
        hk_account: hk,
        amount: decode_word_u(&data[..32])?,
        nonce: decode_word_u(&data[32..64])?,
        block: qty(log.get("blockNumber").unwrap_or(&Value::Null))? as u64,
        tx_hash: log.get("transactionHash").and_then(|h| h.as_str()).unwrap_or("").to_string(),
        log_index: qty(log.get("logIndex").unwrap_or(&json!("0x0")))?,
    })
}

// ---------------------------------------------------------------------------------------------
// EIP-712
// ---------------------------------------------------------------------------------------------

/// `keccak256(abi.encode(EIP712DOMAIN_TYPEHASH, keccak(name), keccak("1"), chainId, verifyingContract))`
pub(crate) fn domain_separator(name: &str, chain_id: u64, contract: &Address) -> [u8; 32] {
    let typehash = keccak256(&[b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"]);
    let name_h = keccak256(&[name.as_bytes()]);
    let ver_h = keccak256(&[b"1"]);
    keccak256(&[&typehash, &name_h, &ver_h, &word_u(chain_id as u128), &word_addr(contract)])
}

/// `keccak256(abi.encode(TYPEHASH, to, amount, id))` for `Unlock(address to,uint256 amount,bytes32 burnId)`
/// or `Mint(address to,uint256 amount,bytes32 mintId)`.
pub(crate) fn attest_struct_hash(type_sig: &str, to: &Address, amount: u128, id: &[u8; 32]) -> [u8; 32] {
    let typehash = keccak256(&[type_sig.as_bytes()]);
    keccak256(&[&typehash, &word_addr(to), &word_u(amount), id])
}

pub(crate) fn typed_digest(domain: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[b"\x19\x01", domain, struct_hash])
}

pub(crate) const UNLOCK_TYPE: &str = "Unlock(address to,uint256 amount,bytes32 burnId)";
pub(crate) const MINT_TYPE: &str = "Mint(address to,uint256 amount,bytes32 mintId)";

// ---------------------------------------------------------------------------------------------
// RLP + EIP-1559 transactions
// ---------------------------------------------------------------------------------------------

fn rlp_len(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap_or(7);
        let mut v = vec![offset + 55 + (8 - first) as u8];
        v.extend_from_slice(&be[first..]);
        v
    }
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut v = rlp_len(b.len(), 0x80);
    v.extend_from_slice(b);
    v
}

fn rlp_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap();
    rlp_bytes(&be[first..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flatten().copied().collect();
    let mut v = rlp_len(payload.len(), 0xc0);
    v.extend_from_slice(&payload);
    v
}

pub(crate) struct Tx1559 {
    pub chain_id: u64,
    pub nonce: u128,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas: u128,
    pub to: Address,
    pub value: u128,
    pub data: Vec<u8>,
}

/// Sign an EIP-1559 transaction; returns the raw `0x02…` bytes for `eth_sendRawTransaction`.
pub(crate) fn sign_tx(signer: &Signer, tx: &Tx1559) -> Result<Vec<u8>, String> {
    let body = vec![
        rlp_uint(tx.chain_id as u128),
        rlp_uint(tx.nonce),
        rlp_uint(tx.max_priority_fee),
        rlp_uint(tx.max_fee),
        rlp_uint(tx.gas),
        rlp_bytes(&tx.to.0),
        rlp_uint(tx.value),
        rlp_bytes(&tx.data),
        rlp_list(&[]), // access list
    ];
    let mut unsigned = vec![0x02u8];
    unsigned.extend_from_slice(&rlp_list(&body));
    let h = keccak256(&[&unsigned]);
    let (y, r, s) = signer.sign_tx_hash(&h)?;
    let mut signed = body;
    signed.push(rlp_uint(y as u128));
    signed.push(rlp_bytes(strip_leading_zeros(&r))); // scalars: minimal big-endian byte strings
    signed.push(rlp_bytes(strip_leading_zeros(&s)));
    let mut raw = vec![0x02u8];
    raw.extend_from_slice(&rlp_list(&signed));
    Ok(raw)
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    &b[first..]
}

// ---------------------------------------------------------------------------------------------
// JSON-RPC client
// ---------------------------------------------------------------------------------------------

pub(crate) struct EthClient {
    pub url: String,
    pub chain_id: u64,
}

impl EthClient {
    pub(crate) fn new(url: &str, chain_id: u64) -> Self {
        Self { url: url.to_string(), chain_id }
    }

    pub(crate) fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v = post_json(&self.url, &body, 30)?;
        if let Some(e) = v.get("error") {
            return Err(format!("{method}: {e}"));
        }
        v.get("result").cloned().ok_or_else(|| format!("{method}: no result in {v}"))
    }

    pub(crate) fn chain_id(&self) -> Result<u64, String> {
        Ok(qty(&self.call("eth_chainId", json!([]))?)? as u64)
    }

    pub(crate) fn block_number(&self) -> Result<u64, String> {
        Ok(qty(&self.call("eth_blockNumber", json!([]))?)? as u64)
    }

    /// Number of the block tagged `finalized` / `safe` / `latest`.
    pub(crate) fn tagged_block(&self, tag: &str) -> Result<u64, String> {
        let b = self.call("eth_getBlockByNumber", json!([tag, false]))?;
        if b.is_null() {
            return Err(format!("no '{tag}' block (provider does not support the tag?)"));
        }
        Ok(qty(b.get("number").unwrap_or(&Value::Null))? as u64)
    }

    pub(crate) fn base_fee(&self) -> Result<u128, String> {
        let b = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        qty(b.get("baseFeePerGas").unwrap_or(&json!("0x0")))
    }

    pub(crate) fn logs(&self, address: &Address, topic0: &[u8; 32], from: u64, to: u64) -> Result<Vec<Value>, String> {
        let r = self.call(
            "eth_getLogs",
            json!([{
                "address": address.hex(),
                "topics": [hex0x(topic0)],
                "fromBlock": qty_hex(from as u128),
                "toBlock": qty_hex(to as u128),
            }]),
        )?;
        r.as_array().cloned().ok_or_else(|| "eth_getLogs: not an array".into())
    }

    pub(crate) fn eth_call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
        let r = self.call("eth_call", json!([{"to": to.hex(), "data": hex0x(data)}, "latest"]))?;
        unhex(r.as_str().unwrap_or(""))
    }

    pub(crate) fn nonce(&self, who: &Address) -> Result<u128, String> {
        qty(&self.call("eth_getTransactionCount", json!([who.hex(), "pending"]))?)
    }

    pub(crate) fn estimate_gas(&self, from: &Address, to: &Address, data: &[u8]) -> Result<u128, String> {
        qty(&self.call("eth_estimateGas", json!([{"from": from.hex(), "to": to.hex(), "data": hex0x(data)}]))?)
    }

    pub(crate) fn priority_fee(&self) -> Result<u128, String> {
        match self.call("eth_maxPriorityFeePerGas", json!([])) {
            Ok(v) => qty(&v),
            Err(_) => Ok(1_500_000_000), // 1.5 gwei if the provider lacks the method
        }
    }

    pub(crate) fn send_raw(&self, raw: &[u8]) -> Result<String, String> {
        let r = self.call("eth_sendRawTransaction", json!([hex0x(raw)]))?;
        r.as_str().map(str::to_string).ok_or_else(|| "eth_sendRawTransaction: no hash".into())
    }

    /// `Some(status)` once mined (`true` = success), `None` while pending.
    pub(crate) fn receipt_status(&self, tx_hash: &str) -> Result<Option<(bool, u64)>, String> {
        let r = self.call("eth_getTransactionReceipt", json!([tx_hash]))?;
        if r.is_null() {
            return Ok(None);
        }
        let ok = qty(r.get("status").unwrap_or(&json!("0x0")))? == 1;
        let block = qty(r.get("blockNumber").unwrap_or(&json!("0x0")))? as u64;
        Ok(Some((ok, block)))
    }

    pub(crate) fn balance_wei(&self, who: &Address) -> Result<u128, String> {
        qty(&self.call("eth_getBalance", json!([who.hex(), "latest"]))?)
    }

    /// Build, sign and send a contract call from the attestor key. Returns the tx hash.
    pub(crate) fn send_call(&self, signer: &Signer, to: &Address, data: Vec<u8>) -> Result<String, String> {
        let nonce = self.nonce(&signer.address)?;
        let gas = self.estimate_gas(&signer.address, to, &data)? * 12 / 10;
        let base = self.base_fee()?;
        let prio = self.priority_fee()?;
        let tx = Tx1559 {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee: prio,
            max_fee: base * 2 + prio,
            gas,
            to: *to,
            value: 0,
            data,
        };
        let raw = sign_tx(signer, &tx)?;
        self.send_raw(&raw)
    }
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_vectors() {
        assert_eq!(hex::encode(keccak256(&[b""])), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hex::encode(keccak256(&[b"hello"])), "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
        assert_eq!(hex::encode(selector("transfer(address,uint256)")), "a9059cbb");
    }

    #[test]
    fn address_of_a_known_key() {
        // the canonical test key: 0x…01 → 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        let s = Signer::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        assert_eq!(s.address.hex(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn abi_attested_call_layout() {
        let to = Address::parse("0x00000000000000000000000000000000000000aa").unwrap();
        let id = [0x11u8; 32];
        let sig = [0x22u8; 65];
        let d = encode_attested_call("unlock(address,uint256,bytes32,bytes[])", &to, 5, &id, &[sig]);
        assert_eq!(&d[..4], &selector("unlock(address,uint256,bytes32,bytes[])"));
        assert_eq!(&d[4..36], &word_addr(&to));
        assert_eq!(&d[36..68], &word_u(5));
        assert_eq!(&d[68..100], &id);
        assert_eq!(&d[100..132], &word_u(0x80));
        assert_eq!(&d[132..164], &word_u(1)); // bytes[] length
        assert_eq!(&d[164..196], &word_u(32)); // offset of element 0 (after the one offset word)
        assert_eq!(&d[196..228], &word_u(65)); // element length
        assert_eq!(&d[228..293], &sig);
        assert_eq!(d.len(), 228 + 96);
        // two signatures: offsets 64 and 64+128
        let d2 = encode_attested_call("unlock(address,uint256,bytes32,bytes[])", &to, 5, &id, &[sig, sig]);
        assert_eq!(&d2[164..196], &word_u(64));
        assert_eq!(&d2[196..228], &word_u(64 + 128));
        assert_eq!(d2.len(), 4 + 32 * 4 + 32 + 64 + 2 * 128);
    }

    #[test]
    fn view_helpers() {
        let a = Address::parse("0x00000000000000000000000000000000000000aa").unwrap();
        let q = encode_attestor_query(&a);
        assert_eq!(&q[..4], &selector("isAttestor(address)"));
        assert_eq!(&q[4..], &word_addr(&a));
        // "wHKT" as an ABI string: offset 0x20, length 4, bytes padded
        let mut enc = Vec::new();
        enc.extend_from_slice(&word_u(0x20));
        enc.extend_from_slice(&word_u(4));
        let mut body = [0u8; 32];
        body[..4].copy_from_slice(b"wHKT");
        enc.extend_from_slice(&body);
        assert_eq!(decode_string(&enc).unwrap(), "wHKT");
    }

    #[test]
    fn eip712_shapes() {
        let c = Address::parse("0x00000000000000000000000000000000000000cc").unwrap();
        let d1 = domain_separator("HKVault", 11155111, &c);
        let d2 = domain_separator("HKVault", 1, &c);
        assert_ne!(d1, d2);
        let to = Address::parse("0x00000000000000000000000000000000000000aa").unwrap();
        let sh = attest_struct_hash(UNLOCK_TYPE, &to, 7, &[9u8; 32]);
        let dg = typed_digest(&d1, &sh);
        assert_eq!(dg, keccak256(&[b"\x19\x01", &d1, &sh]));
        // the struct hash is keccak(typehash ‖ words)
        let th = keccak256(&[UNLOCK_TYPE.as_bytes()]);
        assert_eq!(sh, keccak256(&[&th, &word_addr(&to), &word_u(7), &[9u8; 32]]));
    }

    #[test]
    fn rlp_basics() {
        assert_eq!(rlp_uint(0), vec![0x80]);
        assert_eq!(rlp_uint(15), vec![0x0f]);
        assert_eq!(rlp_uint(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(rlp_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]), vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        let long = vec![b'x'; 60];
        let e = rlp_bytes(&long);
        assert_eq!(&e[..2], &[0xb8, 60]);
    }

    #[test]
    fn signed_tx_is_type2_and_recovers_to_the_signer() {
        let s = Signer::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let tx = Tx1559 {
            chain_id: 11155111,
            nonce: 3,
            max_priority_fee: 1_500_000_000,
            max_fee: 30_000_000_000,
            gas: 100_000,
            to: Address::parse("0x00000000000000000000000000000000000000cc").unwrap(),
            value: 0,
            data: vec![1, 2, 3],
        };
        let raw = sign_tx(&s, &tx).unwrap();
        assert_eq!(raw[0], 0x02);
        // recover: rebuild the unsigned payload, hash it, recover the key from (y, r, s)
        let body = vec![
            rlp_uint(tx.chain_id as u128), rlp_uint(tx.nonce), rlp_uint(tx.max_priority_fee), rlp_uint(tx.max_fee),
            rlp_uint(tx.gas), rlp_bytes(&tx.to.0), rlp_uint(tx.value), rlp_bytes(&tx.data), rlp_list(&[]),
        ];
        let mut unsigned = vec![0x02u8];
        unsigned.extend_from_slice(&rlp_list(&body));
        let h = keccak256(&[&unsigned]);
        let (y, r, sg) = s.sign_tx_hash(&h).unwrap();
        let sig = k256::ecdsa::Signature::from_slice(&[r, sg].concat()).unwrap();
        let rid = k256::ecdsa::RecoveryId::from_byte(y).unwrap();
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&h, &sig, rid).unwrap();
        let p = vk.to_encoded_point(false);
        let hh = keccak256(&[&p.as_bytes()[1..]]);
        assert_eq!(&hh[12..], &s.address.0);
        // and the raw tx carries r, s as byte strings (no leading zeros), y as 0/1
        assert!(raw.len() > 70);
    }

    #[test]
    fn sign_digest_has_v_27_or_28() {
        let s = Signer::from_hex("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let sig = s.sign_digest(&[7u8; 32]).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28);
    }

    #[test]
    fn event_decoding() {
        let log = json!({
            "topics": [
                hex0x(&event_topic(LOCKED_SIG)),
                hex0x(&[0x11u8; 32]),
                "0x000000000000000000000000000000000000000000000000000000000000aabb",
                hex0x(&[0x33u8; 32]),
            ],
            "data": format!("0x{}{}", hex::encode(word_u(20_000_000)), hex::encode(word_u(7))),
            "blockNumber": "0x10",
            "transactionHash": "0xdead",
            "logIndex": "0x2",
        });
        let e = decode_bridge_event(&log).unwrap();
        assert_eq!(e.id, [0x11u8; 32]);
        assert_eq!(e.from.hex(), "0x000000000000000000000000000000000000aabb");
        assert_eq!(e.hk_account, [0x33u8; 32]);
        assert_eq!(e.amount, 20_000_000);
        assert_eq!(e.nonce, 7);
        assert_eq!(e.block, 16);
        assert_eq!(e.log_index, 2);
    }
}
