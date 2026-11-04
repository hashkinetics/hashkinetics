//! The hardware signer's wire format, the suite's half: the CBOR messages `hk-sign-request`,
//! `hk-sign-response`, `hk-pair`, `eth-sign-request` and `eth-sign-response` (v1), the
//! verification code and the device fingerprint. The tests pin them byte for byte to the
//! device's reference vectors for the public TEST wallet (seed 07 x 32). Nothing here holds a
//! secret: the device signs; the suite builds requests and checks answers.
//!
//! Encoding: map keys in each message's fixed order, shortest-form heads, definite lengths (the
//! device's encoding, not RFC 8949's sorted order). Decoding is strict: text keys only; unknown
//! or duplicate keys, indefinite lengths, non-shortest heads, other major types, maps nested
//! deeper than the messages need and trailing bytes are all refused. A request's fields pass one
//! `validate()` both ways: `to_cbor` refuses to write what `from_cbor` would refuse to read.

use hk_crypto::lamport::{PK_LEN, SIG_LEN};
use hk_primitives::H256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::account::derived_id;
use crate::eth::{be_min, Eip1559};
use crate::WalletError;

/// testnet-1's chain id, the only `net` the v1 device accepts.
pub const NET_TESTNET1: &str = "hashkinetics-1-4e4ea68d";

fn err(m: impl std::fmt::Display) -> WalletError {
    WalletError::msg(format!("hardware message: {m}"))
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Errors are shown on screen as they are, so a key read from the wire is named in one only when
/// it is at most 24 bytes of printable ASCII (the device's rule for showing a key) with no quote
/// or backslash, nothing that could close or escape the quotes around it.
fn shown(k: &str) -> Option<&str> {
    (k.len() <= 24 && printable(k) && !k.contains(['"', '\\'])).then_some(k)
}

fn at_most(name: &str, len: usize, max: usize) -> Result<(), WalletError> {
    if len > max {
        return Err(err(format!("\"{name}\" is longer than {max} bytes")));
    }
    Ok(())
}

/// SHAKE-256 over a plain concatenation. The signer's tags are NOT hk-crypto's framed
/// `shake256_32` (no 0x00 separator, no length prefixes): this is what the device computes.
fn shake_plain(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

// ---------------------------------------------------------------------------
// CBOR: the subset the v1 messages use
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cbor {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    /// Text keys, in wire order.
    Map(Vec<(String, Cbor)>),
}

/// A message map nests at most one map (a hint).
const MAX_DEPTH: usize = 2;
const MAX_KEYS: u64 = 16;

fn put_head(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    if v < 24 {
        out.push(m | v as u8);
    } else if v <= 0xff {
        out.extend_from_slice(&[m | 24, v as u8]);
    } else if v <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

impl Cbor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.put(&mut out);
        out
    }

    fn put(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Uint(v) => put_head(out, 0, *v),
            Cbor::Bytes(b) => {
                put_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Text(s) => {
                put_head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Cbor::Map(kv) => {
                put_head(out, 5, kv.len() as u64);
                for (k, v) in kv {
                    put_head(out, 3, k.len() as u64);
                    out.extend_from_slice(k.as_bytes());
                    v.put(out);
                }
            }
        }
    }

    /// One whole message, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Cbor, WalletError> {
        let mut r = Reader { b: bytes, i: 0 };
        let v = r.item(0)?;
        if r.i != bytes.len() {
            return Err(err("trailing bytes"));
        }
        Ok(v)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: u64) -> Result<&[u8], WalletError> {
        let end = usize::try_from(n).ok().and_then(|n| self.i.checked_add(n)).filter(|&e| e <= self.b.len()).ok_or_else(|| err("truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u64), WalletError> {
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 31);
        let (v, min) = match ai {
            0..=23 => (ai as u64, 0),
            24 => (self.take(1)?[0] as u64, 24),
            25 => (u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64, 0x100),
            26 => (u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64, 0x1_0000),
            27 => (u64::from_be_bytes(self.take(8)?.try_into().unwrap()), 0x1_0000_0000),
            _ => return Err(err("indefinite or reserved length")),
        };
        if v < min {
            return Err(err("a length or integer not in its shortest form"));
        }
        Ok((major, v))
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, WalletError> {
        let (major, v) = self.head()?;
        match major {
            0 => Ok(Cbor::Uint(v)),
            2 => Ok(Cbor::Bytes(self.take(v)?.to_vec())),
            3 => self.text(v).map(Cbor::Text),
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(err("maps nested too deep"));
                }
                if v > MAX_KEYS {
                    return Err(err("too many keys"));
                }
                let mut kv: Vec<(String, Cbor)> = Vec::new();
                for _ in 0..v {
                    let (km, kl) = self.head()?;
                    if km != 3 {
                        return Err(err("a map key that is not text"));
                    }
                    let k = self.text(kl)?;
                    if kv.iter().any(|(x, _)| *x == k) {
                        return Err(err(match shown(&k) {
                            Some(k) => format!("duplicate key \"{k}\""),
                            None => "a key that appears twice".into(),
                        }));
                    }
                    let val = self.item(depth + 1)?;
                    kv.push((k, val));
                }
                Ok(Cbor::Map(kv))
            }
            _ => Err(err("a CBOR type the v1 messages do not use")),
        }
    }

    fn text(&mut self, n: u64) -> Result<String, WalletError> {
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| err("text that is not UTF-8"))
    }
}

/// The fields of one message map: each is taken once, by name and type; whatever is left over
/// at the end is an unknown key and refused.
struct Fields {
    kv: Vec<(String, Cbor)>,
}

impl Fields {
    fn of(c: Cbor) -> Result<Self, WalletError> {
        match c {
            Cbor::Map(kv) => Ok(Self { kv }),
            _ => Err(err("not a map")),
        }
    }

    fn take(&mut self, name: &str) -> Option<Cbor> {
        let at = self.kv.iter().position(|(k, _)| k == name)?;
        Some(self.kv.remove(at).1)
    }

    fn uint(&mut self, name: &str) -> Result<u64, WalletError> {
        match self.take(name) {
            Some(Cbor::Uint(v)) => Ok(v),
            Some(_) => Err(err(format!("\"{name}\" is not an unsigned integer"))),
            None => Err(err(format!("\"{name}\" is missing"))),
        }
    }

    fn bytes(&mut self, name: &str) -> Result<Vec<u8>, WalletError> {
        match self.take(name) {
            Some(Cbor::Bytes(b)) => Ok(b),
            Some(_) => Err(err(format!("\"{name}\" is not a byte string"))),
            None => Err(err(format!("\"{name}\" is missing"))),
        }
    }

    fn bytes_max(&mut self, name: &str, max: usize) -> Result<Vec<u8>, WalletError> {
        let b = self.bytes(name)?;
        at_most(name, b.len(), max)?;
        Ok(b)
    }

    fn exact<const N: usize>(&mut self, name: &str) -> Result<[u8; N], WalletError> {
        self.bytes_max(name, N)?.try_into().map_err(|_| err(format!("\"{name}\" must be exactly {N} bytes")))
    }

    /// A uint256 as RLP writes it: at most 32 bytes, big-endian, no leading zero (empty = 0).
    fn uint256(&mut self, name: &str) -> Result<[u8; 32], WalletError> {
        let b = self.bytes_max(name, 32)?;
        if b.first() == Some(&0) {
            return Err(err(format!("\"{name}\" has a leading zero byte")));
        }
        let mut v = [0u8; 32];
        v[32 - b.len()..].copy_from_slice(&b);
        Ok(v)
    }

    fn text(&mut self, name: &str) -> Result<String, WalletError> {
        match self.take(name) {
            Some(Cbor::Text(s)) => Ok(s),
            Some(_) => Err(err(format!("\"{name}\" is not text"))),
            None => Err(err(format!("\"{name}\" is missing"))),
        }
    }

    /// A hint's decimals as a byte. A value too large for one is above every bound `validate()`
    /// allows: it is kept as 255 and refused there.
    fn decimals(&mut self) -> Result<u8, WalletError> {
        Ok(u8::try_from(self.uint("decimals")?).unwrap_or(u8::MAX))
    }

    fn version(&mut self) -> Result<(), WalletError> {
        match self.uint("v")? {
            1 => Ok(()),
            v => Err(err(format!("version {v} (this wallet speaks v1)"))),
        }
    }

    fn done(self) -> Result<(), WalletError> {
        match self.kv.first() {
            Some((k, _)) => Err(err(match shown(k) {
                Some(k) => format!("unknown key \"{k}\""),
                None => "a key this wallet does not know".into(),
            })),
            None => Ok(()),
        }
    }
}

fn m(k: &str, v: Cbor) -> (String, Cbor) {
    (k.to_string(), v)
}

// ---------------------------------------------------------------------------
// The verification code and the device fingerprint
// ---------------------------------------------------------------------------

/// `c = SHAKE-256("HKHW-VERIFY-v1" ‖ the request's bytes as carried)`: `raw` = c[0..4] (shown
/// `XXXX-XXXX`, and echoed in the response's `code`), `band` stripe i = c[4+i] mod 8 (an index
/// into the device's 8-colour Okabe-Ito palette).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyCode {
    pub raw: [u8; 4],
    pub band: [u8; 4],
}

impl VerifyCode {
    pub fn of(request: &[u8]) -> Self {
        let mut c = [0u8; 8];
        shake_plain(&[b"HKHW-VERIFY-v1", request], &mut c);
        Self { raw: [c[0], c[1], c[2], c[3]], band: [c[4] % 8, c[5] % 8, c[6] % 8, c[7] % 8] }
    }

    pub fn text(&self) -> String {
        let h = hex::encode_upper(self.raw);
        format!("{}-{}", &h[..4], &h[4..])
    }
}

/// The first 8 bytes of `SHAKE-256("HKHW-FP-v1" ‖ id ‖ eth address)`, shown at pairing and on
/// every request.
pub fn fingerprint(id: &H256, eth: &[u8; 20]) -> [u8; 8] {
    let mut fp = [0u8; 8];
    shake_plain(&[b"HKHW-FP-v1", &id.0, eth], &mut fp);
    fp
}

// ---------------------------------------------------------------------------
// The messages
// ---------------------------------------------------------------------------

/// Display-only and untrusted: the device names known assets from its own list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkHint {
    pub symbol: String,
    pub decimals: u8,
}

/// `hk-sign-request` v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkSignRequest {
    pub net: String,
    pub sender: H256,
    pub nonce: u64,
    /// The canonical `serde_json` bytes of the `Tx`: exactly what `signing_digest` hashes.
    pub payload: Vec<u8>,
    pub hint: Option<HkHint>,
}

/// A request's payload stays well under one QR screen's worth of frames.
const MAX_PAYLOAD: usize = 4096;

impl HkSignRequest {
    /// The form of every field, checked both ways (by `to_cbor` before it writes, by `from_cbor`
    /// after it reads): what this decoder and the device's parser both accept. Whether the device
    /// will sign the request (network, account, nonce, payload) is its own check, not this one.
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.net.len() > 40 || !printable(&self.net) {
            return Err(err("\"net\" must be at most 40 bytes of printable ASCII"));
        }
        at_most("payload", self.payload.len(), MAX_PAYLOAD)?;
        if let Some(h) = &self.hint {
            if h.symbol.is_empty() || h.symbol.len() > 16 || !printable(&h.symbol) {
                return Err(err("the hint's \"symbol\" must be 1 to 16 bytes of printable ASCII"));
            }
            if h.decimals > 18 {
                return Err(err("hint decimals above 18"));
            }
        }
        Ok(())
    }

    /// The message map as it is, unchecked: `to_cbor` validates first.
    fn cbor(&self) -> Cbor {
        let mut kv = vec![
            m("v", Cbor::Uint(1)),
            m("net", Cbor::Text(self.net.clone())),
            m("sender", Cbor::Bytes(self.sender.0.to_vec())),
            m("nonce", Cbor::Uint(self.nonce)),
            m("payload", Cbor::Bytes(self.payload.clone())),
        ];
        if let Some(h) = &self.hint {
            kv.push(m("hint", Cbor::Map(vec![m("symbol", Cbor::Text(h.symbol.clone())), m("decimals", Cbor::Uint(h.decimals as u64))])));
        }
        Cbor::Map(kv)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, WalletError> {
        self.validate()?;
        Ok(self.cbor().encode())
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WalletError> {
        let mut f = Fields::of(Cbor::decode(bytes)?)?;
        f.version()?;
        let net = f.text("net")?;
        let sender = H256(f.exact::<32>("sender")?);
        let nonce = f.uint("nonce")?;
        let payload = f.bytes("payload")?;
        let hint = match f.take("hint") {
            None => None,
            Some(h) => {
                let mut h = Fields::of(h)?;
                let symbol = h.text("symbol")?;
                let decimals = h.decimals()?;
                h.done()?;
                Some(HkHint { symbol, decimals })
            }
        };
        f.done()?;
        let r = Self { net, sender, nonce, payload, hint };
        r.validate()?;
        Ok(r)
    }
}

/// `hk-sign-response` v1: the parts of a `SignedTx` plus the request's code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkSignResponse {
    pub sender: H256,
    pub nonce: u64,
    /// Echo of the request's payload bytes.
    pub payload: Vec<u8>,
    pub next_auth: H256,
    pub lamport_pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub code: [u8; 4],
}

impl HkSignResponse {
    pub fn to_cbor(&self) -> Vec<u8> {
        Cbor::Map(vec![
            m("v", Cbor::Uint(1)),
            m("sender", Cbor::Bytes(self.sender.0.to_vec())),
            m("nonce", Cbor::Uint(self.nonce)),
            m("payload", Cbor::Bytes(self.payload.clone())),
            m("next_auth", Cbor::Bytes(self.next_auth.0.to_vec())),
            m("lamport_pk", Cbor::Bytes(self.lamport_pk.clone())),
            m("sig", Cbor::Bytes(self.sig.clone())),
            m("code", Cbor::Bytes(self.code.to_vec())),
        ])
        .encode()
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WalletError> {
        let mut f = Fields::of(Cbor::decode(bytes)?)?;
        f.version()?;
        let r = Self {
            sender: H256(f.exact::<32>("sender")?),
            nonce: f.uint("nonce")?,
            payload: f.bytes_max("payload", MAX_PAYLOAD)?,
            next_auth: H256(f.exact::<32>("next_auth")?),
            lamport_pk: f.exact::<PK_LEN>("lamport_pk")?.to_vec(),
            sig: f.exact::<SIG_LEN>("sig")?.to_vec(),
            code: f.exact::<4>("code")?,
        };
        f.done()?;
        Ok(r)
    }
}

/// `hk-pair` v1 as the device sends it: the closed map { v, id, auth0, eth, fp }; any other key
/// is refused. An attestation would come as v2, once the device has its own secure element (on
/// the chip it carries now, an attestation key would take a one-way key generation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkPair {
    pub id: H256,
    pub auth0: H256,
    pub eth: [u8; 20],
    pub fp: [u8; 8],
}

impl HkPair {
    pub fn to_cbor(&self) -> Vec<u8> {
        Cbor::Map(vec![
            m("v", Cbor::Uint(1)),
            m("id", Cbor::Bytes(self.id.0.to_vec())),
            m("auth0", Cbor::Bytes(self.auth0.0.to_vec())),
            m("eth", Cbor::Bytes(self.eth.to_vec())),
            m("fp", Cbor::Bytes(self.fp.to_vec())),
        ])
        .encode()
    }

    /// Decodes and checks what the suite can check itself: the id is the one consensus derives
    /// from `auth0`, and the fingerprint matches id and address.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WalletError> {
        let mut f = Fields::of(Cbor::decode(bytes)?)?;
        f.version()?;
        let p = Self { id: H256(f.exact::<32>("id")?), auth0: H256(f.exact::<32>("auth0")?), eth: f.exact::<20>("eth")?, fp: f.exact::<8>("fp")? };
        f.done()?;
        if derived_id(&p.auth0) != p.id {
            return Err(err("the account id does not follow from auth0"));
        }
        if fingerprint(&p.id, &p.eth) != p.fp {
            return Err(err("the fingerprint does not match the id and address"));
        }
        Ok(p)
    }
}

/// Display-only and untrusted, like [`HkHint`]: the device names known tokens from its own list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthHint {
    pub symbol: String,
    pub decimals: u8,
    pub contract: [u8; 20],
}

/// `eth-sign-request` v1: an EIP-1559 transaction for the device to show and sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthSignRequest {
    pub chain_id: u64,
    pub from: [u8; 20],
    pub nonce: u64,
    pub max_fee: u64,
    pub max_priority: u64,
    pub gas: u64,
    pub to: [u8; 20],
    /// Wei, a uint256, big-endian; on the wire without leading zeros (empty = 0).
    pub value: [u8; 32],
    pub data: Vec<u8>,
    pub hint: Option<EthHint>,
}

impl EthSignRequest {
    /// The form of every field, checked both ways as for [`HkSignRequest::validate`]; `value` is
    /// a uint256 and needs no check. Whether the device will sign the request (account, chain,
    /// fees, gas, the call) is its own check, not this one.
    pub fn validate(&self) -> Result<(), WalletError> {
        at_most("data", self.data.len(), MAX_PAYLOAD)?;
        if let Some(h) = &self.hint {
            at_most("symbol", h.symbol.len(), 16)?;
            if h.decimals > 36 {
                return Err(err("hint decimals above 36"));
            }
        }
        Ok(())
    }

    /// The message map as it is, unchecked: `to_cbor` validates first.
    fn cbor(&self) -> Cbor {
        let mut kv = vec![
            m("v", Cbor::Uint(1)),
            m("chain_id", Cbor::Uint(self.chain_id)),
            m("from", Cbor::Bytes(self.from.to_vec())),
            m("nonce", Cbor::Uint(self.nonce)),
            m("max_fee", Cbor::Uint(self.max_fee)),
            m("max_priority", Cbor::Uint(self.max_priority)),
            m("gas", Cbor::Uint(self.gas)),
            m("to", Cbor::Bytes(self.to.to_vec())),
            m("value", Cbor::Bytes(be_min(&self.value).to_vec())),
            m("data", Cbor::Bytes(self.data.clone())),
        ];
        if let Some(h) = &self.hint {
            kv.push(m(
                "hint",
                Cbor::Map(vec![m("symbol", Cbor::Text(h.symbol.clone())), m("decimals", Cbor::Uint(h.decimals as u64)), m("contract", Cbor::Bytes(h.contract.to_vec()))]),
            ));
        }
        Cbor::Map(kv)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, WalletError> {
        self.validate()?;
        Ok(self.cbor().encode())
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WalletError> {
        let mut f = Fields::of(Cbor::decode(bytes)?)?;
        f.version()?;
        let r = Self {
            chain_id: f.uint("chain_id")?,
            from: f.exact::<20>("from")?,
            nonce: f.uint("nonce")?,
            max_fee: f.uint("max_fee")?,
            max_priority: f.uint("max_priority")?,
            gas: f.uint("gas")?,
            to: f.exact::<20>("to")?,
            value: f.uint256("value")?,
            data: f.bytes("data")?,
            hint: match f.take("hint") {
                None => None,
                Some(h) => {
                    let mut h = Fields::of(h)?;
                    let symbol = h.text("symbol")?;
                    let decimals = h.decimals()?;
                    let contract = h.exact::<20>("contract")?;
                    h.done()?;
                    Some(EthHint { symbol, decimals, contract })
                }
            },
        };
        f.done()?;
        r.validate()?;
        Ok(r)
    }

    pub fn tx(&self) -> Eip1559 {
        Eip1559 {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority: self.max_priority,
            max_fee: self.max_fee,
            gas: self.gas,
            to: self.to,
            value: self.value,
            data: self.data.clone(),
        }
    }
}

/// `eth-sign-response` v1: the signed transaction, its hash and the request's code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthSignResponse {
    pub chain_id: u64,
    pub from: [u8; 20],
    pub nonce: u64,
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
    pub code: [u8; 4],
}

impl EthSignResponse {
    pub fn to_cbor(&self) -> Vec<u8> {
        Cbor::Map(vec![
            m("v", Cbor::Uint(1)),
            m("chain_id", Cbor::Uint(self.chain_id)),
            m("from", Cbor::Bytes(self.from.to_vec())),
            m("nonce", Cbor::Uint(self.nonce)),
            m("raw", Cbor::Bytes(self.raw.clone())),
            m("hash", Cbor::Bytes(self.hash.to_vec())),
            m("code", Cbor::Bytes(self.code.to_vec())),
        ])
        .encode()
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WalletError> {
        let mut f = Fields::of(Cbor::decode(bytes)?)?;
        f.version()?;
        let r = Self {
            chain_id: f.uint("chain_id")?,
            from: f.exact::<20>("from")?,
            nonce: f.uint("nonce")?,
            raw: f.bytes_max("raw", MAX_PAYLOAD + 512)?,
            hash: f.exact::<32>("hash")?,
            code: f.exact::<4>("code")?,
        };
        f.done()?;
        Ok(r)
    }
}

/// Everything the suite checks before it broadcasts a device's Ethereum signature: the response
/// answers THIS request (chain, sender, nonce, verification code), the request is from the
/// paired address, `raw` is exactly the requested transaction with a low s and recovers to that
/// address, and `hash` is keccak256(raw).
pub fn check_eth_response(request: &[u8], response: &[u8], paired: &[u8; 20]) -> Result<EthSignResponse, WalletError> {
    let req = EthSignRequest::from_cbor(request)?;
    let resp = EthSignResponse::from_cbor(response)?;
    if req.from != *paired {
        return Err(err("the request is not from the paired device's address"));
    }
    if (resp.chain_id, resp.from, resp.nonce) != (req.chain_id, req.from, req.nonce) {
        return Err(err("the response answers another request"));
    }
    if resp.code != VerifyCode::of(request).raw {
        return Err(err("the verification code does not match the request"));
    }
    let hash = req.tx().check_signed(&resp.raw, paired)?;
    if hash != resp.hash {
        return Err(err("\"hash\" is not keccak256 of the signed bytes"));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{commit_at, sign_tx};
    use hk_crypto::lamport;
    use hk_state::tx::{signing_digest, Tx};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // The device's reference vectors for the public TEST wallet (seed 07 x 32); the recipient is
    // the 08 x 32 test account. TEST VALUES ONLY.
    const HK_ID: &str = "cb1c612799a1fc9f0c45acf7ecffca0262c2c4dd3177e37cc0f8af638cae4225";
    const COMMIT0: &str = "031a55b06033fb7f3ea3348a14e54e7644d65d029eb2ee3680acc231d0f2de6b";
    const ETH_ADDR: &str = "29458c602e3db4fc3b54ec2bbee26dbe64c7779f";
    const FINGERPRINT: &str = "d0780d10cebb6f06";
    const RECIPIENT: &str = "55212e596c1e1c252c72ff9aacbe625241e0c3e28919c4bbda54a6081e8b6a34";
    const DEMO_PAYLOAD: &str = "7b225472616e73666572223a7b22746f223a5b38352c33332c34362c38392c3130382c33302c32382c33372c34342c3131342c3235352c3135342c3137322c3139302c39382c38322c36352c3232342c3139352c3232362c3133372c32352c3139362c3138372c3231382c38342c3136362c382c33302c3133392c3130362c35325d2c226173736574223a5b392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c392c395d2c22616d6f756e74223a323530303030307d7d";
    const DEMO_HEAD: &str = "a6617601636e657477686173686b696e65746963732d";
    const DEMO_TAIL: &str = "6468696e74a26673796d626f6c63484b4e68646563696d616c7306";
    const RESP_FP: &str = "b3afdffc2475d515aa6ad5024425c446";
    const RESP_LEN: usize = 24936;
    const RESP_NEXT_AUTH: &str = "dc393ef9993b9e98c6af86d065b1e99454d68016db688ec4f2dab092b5e98cb5";
    const PAIR: &str = "a56176016269645820cb1c612799a1fc9f0c45acf7ecffca0262c2c4dd3177e37cc0f8af638cae42256561757468305820031a55b06033fb7f3ea3348a14e54e7644d65d029eb2ee3680acc231d0f2de6b636574685429458c602e3db4fc3b54ec2bbee26dbe64c7779f62667048d0780d10cebb6f06";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn h32(s: &str) -> H256 {
        H256(h(s).try_into().unwrap())
    }

    /// The entries of a message map, to edit and encode again.
    fn entries(bytes: &[u8]) -> Vec<(String, Cbor)> {
        match Cbor::decode(bytes).unwrap() {
            Cbor::Map(kv) => kv,
            _ => unreachable!(),
        }
    }

    /// The device's demo request: net-suffix ‖ "sender" 32 bytes ‖ nonce 0 ‖ the payload ‖ hint.
    fn demo_bytes(net_suffix: &str, sender: &str) -> Vec<u8> {
        let mut b = h(DEMO_HEAD);
        b.extend_from_slice(net_suffix.as_bytes());
        b.extend_from_slice(&h("6673656e6465725820"));
        b.extend_from_slice(&h(sender));
        b.extend_from_slice(&h("656e6f6e636500677061796c6f616458df"));
        b.extend_from_slice(&h(DEMO_PAYLOAD));
        b.extend_from_slice(&h(DEMO_TAIL));
        b
    }

    fn transfer() -> Tx {
        Tx::Transfer { to: h32(RECIPIENT), asset: H256([9u8; 32]), amount: 2_500_000 }
    }

    fn demo(net: &str, sender: H256) -> HkSignRequest {
        let payload = serde_json::to_vec(&transfer()).unwrap();
        HkSignRequest { net: net.into(), sender, nonce: 0, payload, hint: Some(HkHint { symbol: "HKN".into(), decimals: 6 }) }
    }

    /// Whether the suite takes this request. Its encoder and its decoder must agree: `to_cbor`
    /// refuses exactly when `from_cbor` refuses the same map written unchecked, and a request
    /// that passes comes back unchanged from its own bytes.
    fn hk_takes(r: &HkSignRequest) -> bool {
        let unchecked = r.cbor().encode();
        let (sent, back) = (r.to_cbor(), HkSignRequest::from_cbor(&unchecked));
        assert_eq!(sent.is_ok(), back.is_ok(), "{r:?}");
        if let (Ok(sent), Ok(back)) = (&sent, &back) {
            assert_eq!(*sent, unchecked);
            assert_eq!(back, r);
        }
        sent.is_ok()
    }

    #[test]
    fn hw_test_wallet_ids_are_the_devices() {
        let seed = [7u8; 32];
        assert_eq!(commit_at(&seed, 0), h32(COMMIT0));
        assert_eq!(derived_id(&commit_at(&seed, 0)), h32(HK_ID));
        assert_eq!(derived_id(&commit_at(&[8u8; 32], 0)), h32(RECIPIENT));
    }

    #[test]
    fn hw_serde_payload_is_the_bytes_the_device_shows_and_hashes() {
        // The device parses this JSON, re-serialises it and requires byte-equality; the node
        // recomputes the digest from serde's bytes. They must be the same 223 bytes.
        assert_eq!(serde_json::to_vec(&transfer()).unwrap(), h(DEMO_PAYLOAD));
    }

    #[test]
    fn hw_requests_and_codes_are_the_devices() {
        let cases = [
            (demo(NET_TESTNET1, h32(HK_ID)), demo_bytes("1-4e4ea68d", HK_ID), "84F2-5230", [6, 5, 1, 5]),
            // demo 4: another account's request (the device refuses it), demo 5: another network.
            (demo(NET_TESTNET1, h32(RECIPIENT)), demo_bytes("1-4e4ea68d", RECIPIENT), "C44F-7DC3", [3, 2, 3, 3]),
            (demo("hashkinetics-2-00000000", h32(HK_ID)), demo_bytes("2-00000000", HK_ID), "430C-14E9", [4, 6, 4, 4]),
        ];
        for (req, want, code, band) in cases {
            let bytes = req.to_cbor().unwrap();
            assert_eq!(bytes.len(), 340);
            assert_eq!(hex::encode(&bytes), hex::encode(&want));
            let vc = VerifyCode::of(&bytes);
            assert_eq!(vc.text(), code);
            assert_eq!(vc.band, band);
            assert_eq!(HkSignRequest::from_cbor(&bytes).unwrap(), req);
        }
    }

    #[test]
    fn hw_response_is_the_devices_and_verifies() {
        let seed = [7u8; 32];
        let id = h32(HK_ID);
        let req = demo(NET_TESTNET1, id).to_cbor().unwrap();
        let signed = sign_tx(&seed, id, 0, transfer());
        let resp = HkSignResponse {
            sender: signed.sender,
            nonce: signed.nonce,
            payload: serde_json::to_vec(&signed.payload).unwrap(),
            next_auth: signed.next_auth,
            lamport_pk: signed.lamport_pk.clone(),
            sig: signed.sig.clone(),
            code: VerifyCode::of(&req).raw,
        };
        let bytes = resp.to_cbor();
        assert_eq!(bytes.len(), RESP_LEN);
        let mut fp = [0u8; 16];
        shake_plain(&[&bytes], &mut fp);
        assert_eq!(hex::encode(fp), RESP_FP);
        assert_eq!(resp.next_auth, h32(RESP_NEXT_AUTH));
        // The suite's own checks pass on what came back.
        let back = HkSignResponse::from_cbor(&bytes).unwrap();
        assert_eq!(back, resp);
        let tx: Tx = serde_json::from_slice(&back.payload).unwrap();
        let digest = signing_digest(&tx, &back.sender, back.nonce, &back.next_auth).unwrap();
        lamport::verify(&back.lamport_pk, &digest, &back.sig).unwrap();
        assert_eq!(H256(lamport::pk_commit(&back.lamport_pk)), commit_at(&seed, 0));
    }

    #[test]
    fn hw_pairing_is_the_devices_and_checks_itself() {
        let eth: [u8; 20] = h(ETH_ADDR).try_into().unwrap();
        let id = h32(HK_ID);
        assert_eq!(hex::encode(fingerprint(&id, &eth)), FINGERPRINT);
        let pair = HkPair { id, auth0: h32(COMMIT0), eth, fp: fingerprint(&id, &eth) };
        assert_eq!(hex::encode(pair.to_cbor()), PAIR);
        assert_eq!(HkPair::from_cbor(&h(PAIR)).unwrap(), pair);
        // v1 is a closed map: an `attest` key is refused, not ignored.
        let mut kv = entries(&h(PAIR));
        kv.push(m("attest", Cbor::Bytes(vec![0; 64])));
        assert!(HkPair::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("unknown key \"attest\""));
        // A pairing whose id does not follow from auth0, or whose fingerprint is off, is refused.
        let mut bad = pair.clone();
        bad.auth0 = H256([1u8; 32]);
        assert!(HkPair::from_cbor(&bad.to_cbor()).is_err());
        let mut bad = pair;
        bad.fp[0] ^= 1;
        assert!(HkPair::from_cbor(&bad.to_cbor()).is_err());
    }

    // The device's eth-sign-responses to its demo requests 1 (12.5 USDC) and 2 (0.01 ETH) on Base
    // Sepolia, from its reference vectors for the TEST wallet, which signs deterministically (the
    // device hedges its ECDSA nonces with RNG bytes for a wallet entered by its words).
    const DEMO1_RESP: &str = "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b402f8b183014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c001a0fff4f4463f487fc065eda80dd6fd17bceb3da4313a916f2d1ab7c95339ab2391a0250de4538a48169ee47566fbd673f1443d3c2326da6fa97441a7eb5def72367564686173685820b5679831534d7ce721bf0f8f53a48ca458552d71ba5be39e85889c7dfeac763e64636f64654413c445bf";
    const DEMO2_RESP: &str = "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e63650063726177587602f87383014a3480830f42408405f5e100825208949858effd232b4033e47d90003d41ec34ecaeda94872386f26fc1000080c001a0064c85062682c74348eb44418018e2871b1ee0fd0a5189e01ad4a035af167165a00221b3fae3f915bc752deb2ecb312fe1e34b738545c4ac9d4108071a0117c71c646861736858200fbb52e73954b6f4981ce3a9a14f1aeee721b28d9f33e77c23dd000a8b45aeba64636f646544eba91f68";
    const USDC_BASE_SEPOLIA: &str = "036cbd53842c5426634e7929541ec2318f3dcf7e";
    const DEMO_TO: &str = "9858effd232b4033e47d90003d41ec34ecaeda94";

    fn a20(s: &str) -> [u8; 20] {
        h(s).try_into().unwrap()
    }

    /// A uint256 from big-endian bytes, left-padded.
    fn u256(b: &[u8]) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[32 - b.len()..].copy_from_slice(b);
        v
    }

    /// The device's demo request `which`, field for field.
    fn eth_demo(which: u8) -> EthSignRequest {
        let (usdc, to) = (a20(USDC_BASE_SEPOLIA), a20(DEMO_TO));
        let base = EthSignRequest { chain_id: 84532, from: a20(ETH_ADDR), nonce: 0, max_fee: 100_000_000, max_priority: 1_000_000, gas: 0, to: [0; 20], value: [0; 32], data: vec![], hint: None };
        if which == 1 {
            let mut data = h("a9059cbb");
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(&to);
            let mut amount = [0u8; 32];
            amount[24..].copy_from_slice(&12_500_000u64.to_be_bytes());
            data.extend_from_slice(&amount);
            EthSignRequest { gas: 65_000, to: usdc, data, hint: Some(EthHint { symbol: "USDC".into(), decimals: 6, contract: usdc }), ..base }
        } else {
            EthSignRequest { gas: 21_000, to, value: u256(&h("2386f26fc10000")), ..base }
        }
    }

    /// As `hk_takes`, for an eth-sign-request.
    fn eth_takes(r: &EthSignRequest) -> bool {
        let unchecked = r.cbor().encode();
        let (sent, back) = (r.to_cbor(), EthSignRequest::from_cbor(&unchecked));
        assert_eq!(sent.is_ok(), back.is_ok(), "{r:?}");
        if let (Ok(sent), Ok(back)) = (&sent, &back) {
            assert_eq!(*sent, unchecked);
            assert_eq!(back, r);
        }
        sent.is_ok()
    }

    #[test]
    fn hw_eth_requests_and_the_devices_responses_check_out() {
        let paired = a20(ETH_ADDR);
        for (which, resp, code) in [(1, DEMO1_RESP, "13C4-45BF"), (2, DEMO2_RESP, "EBA9-1F68")] {
            let req = eth_demo(which).to_cbor().unwrap();
            // The code inside the device's response was computed over the device's request
            // bytes: matching it proves this encoding is the device's, byte for byte.
            assert_eq!(VerifyCode::of(&req).text(), code);
            assert_eq!(EthSignRequest::from_cbor(&req).unwrap(), eth_demo(which));
            let back = check_eth_response(&req, &h(resp), &paired).unwrap();
            assert_eq!(hex::encode(back.to_cbor()), resp);
        }
    }

    #[test]
    fn hw_eth_checks_refuse_what_was_not_requested() {
        let paired = a20(ETH_ADDR);
        let req = eth_demo(1).to_cbor().unwrap();
        let good = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap();
        let check = |r: &EthSignResponse| check_eth_response(&req, &r.to_cbor(), &paired);
        assert!(check(&good).is_ok());
        // Checked for another paired address: the request is not from it.
        let e = check_eth_response(&req, &good.to_cbor(), &a20(DEMO_TO)).unwrap_err().to_string();
        assert!(e.contains("not from the paired device"), "{e}");
        // One unit more in the calldata's amount (0x…bebc20 → 0x…bebc21: bit 0 of the last data
        // byte, which sits 69 bytes from the end: access list, y, r and s follow it), the hash,
        // the code, the nonce.
        let mut r = good.clone();
        let n = r.raw.len();
        r.raw[n - 69] ^= 1;
        r.hash = crate::eth::keccak256(&r.raw);
        assert!(check(&r).is_err());
        let mut r = good.clone();
        r.hash[0] ^= 1;
        assert!(check(&r).is_err());
        let mut r = good.clone();
        r.code[0] ^= 1;
        assert!(check(&r).is_err());
        let mut r = good.clone();
        r.nonce = 1;
        assert!(check(&r).is_err());
        // The same signature's high-s twin (s → n − s, parity flipped) recovers the same key,
        // and EIP-2 still refuses it.
        const N: [u8; 32] = hex_literal(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let (y, rr, s) = (good.raw[n - 67], &good.raw[n - 65..n - 33], &good.raw[n - 32..]);
        let mut s2 = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = N[i] as i16 - s[i] as i16 - borrow;
            s2[i] = d.rem_euclid(256) as u8;
            borrow = (d < 0) as i16;
        }
        let mut r = good.clone();
        r.raw = eth_demo(1).tx().signed(1 - y, &rr.try_into().unwrap(), &s2);
        r.hash = crate::eth::keccak256(&r.raw);
        assert!(check(&r).unwrap_err().to_string().contains("high s"));
    }

    // The device's eth-sign-responses for the encodings the two demos at nonce 0 do not reach,
    // from its reference vectors. The TEST wallet, deterministic: demo 1 at nonce 5 and demo 2 at
    // nonce 4 (y 0, written 0x80), demo 1 at nonce 184 (RLP 0x81 0xb8, a 31-byte r) and at nonce
    // 128 (0x81 0x80). Hedged with RNG bytes, nonce 0: a 31-byte r or s, y 0 and 1.
    const EDGE: [(u8, u64, &str); 10] = [
        (1, 5, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365056372617758b402f8b183014a3405830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c080a0bf60fed98ddb383a9c57c3face7753f6f157d39deb8382447253f17b849a2117a00be0178e76c78c0de59170c0aef1af3da74f63b96b3b4afd8cc843df0decfbfc646861736858204ef3f0ccce91a596acb40cea711458e59c8d4189c48e4fe1ba01680a0f492c1b64636f6465443adcbe96"),
        (2, 4, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e63650463726177587602f87383014a3404830f42408405f5e100825208949858effd232b4033e47d90003d41ec34ecaeda94872386f26fc1000080c080a0445fbfb62e60889f3501c22ba8e0ee5b7a64065b36b44720b46db29f2c9dcc51a01a34c8f4e7fec01966142f8425f725a3de3f6b50303c47adef711623974f932064686173685820399ba61d5b5960d942544351e4d31e0873fd1b12f2f0a05853fdcce000d1117464636f646544525a3003"),
        (1, 184, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e636518b86372617758b402f8b183014a3481b8830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c0019fc1562efcce12932a290acc794dbdc4fb115469db71dd82e21ad09f60b1f241a06697bc41631d0227550ce127da64f3f11a6b87ab469f32f028316edf62201c88646861736858208ee76a67f39db2cf40fce00f6352a28dbf0c543b60336e740e8e004e460ebeba64636f646544b368877c"),
        (1, 128, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e636518806372617758b502f8b283014a348180830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c001a04a4c9c2d4c43a3a3885f942ed8665ff20b13c7eeab640a535983b59b8059c6c4a033f5c1d580ae27ea682dc6891f01110a400aefc8038c4e4e6b1c9026d9df938a6468617368582033dfe7e16916942ac01c1268e9f86248f3fb50f761ed5eac5fedb0ab78d6e4d364636f646544fb9a34cb"),
        // hedged, RNG fill 0x15: r 31 B, y 1
        (1, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b302f8b083014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c0019ff399dfb8c9dc444496e3d9182deb4996763c845667101af644ebddd8d01d43a0586a1a9ffe217b6a31a8c4fe524706f096e86c6aa64f2f4b72e51b14aea634f66468617368582036004ba7f683377ebf7f462e9240c0881b59200db45d5a790d4b4efcae9f2ac464636f64654413c445bf"),
        // 0x42: y 1
        (1, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b402f8b183014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c001a058c083327a521614727758e59911276d305c7dc8ac581a9df0e6b54236c30a6ea051b14fc4b21e557ee2d0ef9f115d0ffb2781e8e4618fec6dc95950112e85a1c364686173685820efd7262014b02cfc55142049b47feca192126b785469aba84be30ff22481214764636f64654413c445bf"),
        // 0x43: y 0
        (1, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b402f8b183014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c080a089c7dafe1116cfe95c5182668c6eae64a7722d387e72518174fa8b80673fc6e2a0672d24cf58aa39618f1de668e79f04974bf4165b89218eddfd54e6cdc9a331496468617368582090b9ff902c1155d5acc4d377ebc1e035c4634a91aef1c6f98f1fd2ced78ee58564636f64654413c445bf"),
        // 0xa8: s 31 B, y 1
        (1, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b302f8b083014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c001a03903a3a2b658ffd9def791a98ff1f7ab552ba09200088055a430f76ed67d2cc89f3f9d64ba072f7775d993b4fc20ad2fa3d48ced518c4f2cdaccee74adc79de16468617368582033aa936266db6e3344e5235ae27c2e19f578f441591a9255de32393409202d7464636f64654413c445bf"),
        // demo 2, 0x1d: r 31 B, y 0
        (2, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e63650063726177587502f87283014a3480830f42408405f5e100825208949858effd232b4033e47d90003d41ec34ecaeda94872386f26fc1000080c0809f5533aa9ac4d57399d85a9c9248c74e27c1579eecdf7740b8b1647769d4b710a075073dcb1d3352c29c8b450531047e4191aefb6f35c1ca4b5c8f25613b27592564686173685820c17ee379089fc24083cda283c81fdff34728f76f9b4953bce7e5d945989b97eb64636f646544eba91f68"),
        // demo 2, 0x29: s 31 B, y 1
        (2, 0, "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e63650063726177587502f87283014a3480830f42408405f5e100825208949858effd232b4033e47d90003d41ec34ecaeda94872386f26fc1000080c001a0b0de30bdb15649ecd7566d2690b80c4477ef0e4c8129f30ddee9fec88f5bb6359f43ef7503cae5b31d54f5f5d20b8c88ec0f671b5c6c24b63e23bc805e104bd764686173685820497c95abab3f1c8ec7e0e9c18d76e3afbe032bdfc27ec45474c4f678503910d364636f646544eba91f68"),
    ];

    #[test]
    fn hw_eth_edge_encodings_are_the_devices() {
        let paired = a20(ETH_ADDR);
        for (which, nonce, resp) in EDGE {
            let req = EthSignRequest { nonce, ..eth_demo(which) }.to_cbor().unwrap();
            let back = check_eth_response(&req, &h(resp), &paired).unwrap();
            assert_eq!(hex::encode(back.to_cbor()), resp);
        }
        let not_requested = |req: &EthSignRequest, mut r: EthSignResponse| {
            r.hash = crate::eth::keccak256(&r.raw);
            let e = check_eth_response(&req.to_cbor().unwrap(), &r.to_cbor(), &paired).unwrap_err();
            assert!(e.to_string().contains("not the requested transaction"), "{e}");
        };
        // y 0 written 0x00 instead of RLP's empty string 0x80: the same number, other bytes.
        let req = EthSignRequest { nonce: 5, ..eth_demo(1) };
        let mut r = EthSignResponse::from_cbor(&h(EDGE[0].2)).unwrap();
        let n = r.raw.len();
        assert_eq!(r.raw[n - 67], 0x80);
        r.raw[n - 67] = 0x00;
        not_requested(&req, r);
        // The 31-byte r padded back to 32 with a leading zero (the list grows by one byte).
        let req = EthSignRequest { nonce: 184, ..eth_demo(1) };
        let mut r = EthSignResponse::from_cbor(&h(EDGE[2].2)).unwrap();
        let n = r.raw.len();
        assert_eq!((r.raw[1], r.raw[n - 65]), (0xf8, 0x9f));
        let mut raw = r.raw[..n - 65].to_vec();
        raw[2] += 1;
        raw.extend_from_slice(&[0xa0, 0x00]);
        raw.extend_from_slice(&r.raw[n - 64..]);
        r.raw = raw;
        not_requested(&req, r);
        // Nonce 5 written 0x81 0x05 instead of 0x05.
        let req = EthSignRequest { nonce: 5, ..eth_demo(1) };
        let mut r = EthSignResponse::from_cbor(&h(EDGE[0].2)).unwrap();
        assert_eq!(&r.raw[6..8], &[0x34, 0x05]);
        let mut raw = r.raw[..7].to_vec();
        raw[2] += 1;
        raw.extend_from_slice(&[0x81, 0x05]);
        raw.extend_from_slice(&r.raw[8..]);
        r.raw = raw;
        not_requested(&req, r);
    }

    const fn hex_literal(s: &[u8; 64]) -> [u8; 32] {
        const fn nib(c: u8) -> u8 {
            if c <= b'9' {
                c - b'0'
            } else {
                c - b'a' + 10
            }
        }
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn hw_decoding_is_strict() {
        let good = demo(NET_TESTNET1, h32(HK_ID)).to_cbor().unwrap();
        // Trailing and truncated bytes.
        let mut b = good.clone();
        b.push(0);
        assert!(HkSignRequest::from_cbor(&b).is_err());
        assert!(HkSignRequest::from_cbor(&good[..good.len() - 1]).is_err());
        // An unknown key (the map grows to 7 entries) and a duplicate one, each refused for that
        // reason and not another.
        let mut kv = entries(&good);
        kv.push(m("extra", Cbor::Uint(0)));
        assert!(HkSignRequest::from_cbor(&Cbor::Map(kv.clone()).encode()).unwrap_err().to_string().contains("unknown key \"extra\""));
        kv.pop();
        kv.push(m("nonce", Cbor::Uint(1)));
        assert!(HkSignRequest::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("duplicate key \"nonce\""));
        // Non-shortest heads; an indefinite length and a non-text key, each refused for that
        // reason; the shortest head for 24 still decodes; a wrong version.
        assert!(Cbor::decode(&[0x18, 0x05]).is_err());
        assert!(Cbor::decode(&[0x19, 0x00, 0xff]).is_err());
        assert!(Cbor::decode(&[0xbf, 0xff]).unwrap_err().to_string().contains("indefinite"));
        assert!(Cbor::decode(&[0xa1, 0x01, 0x01]).unwrap_err().to_string().contains("not text"));
        assert_eq!(Cbor::decode(&[0x18, 0x18]).unwrap(), Cbor::Uint(24));
        let mut v2 = good.clone();
        v2[3] = 0x02; // "v": 1 → 2
        assert!(HkSignRequest::from_cbor(&v2).is_err());
        // Maps nested deeper than a hint.
        let deep = Cbor::Map(vec![m("a", Cbor::Map(vec![m("b", Cbor::Map(vec![]))]))]).encode();
        assert!(Cbor::decode(&deep).is_err());
        // A response whose pk is a byte short.
        let resp = HkSignResponse {
            sender: H256([0u8; 32]),
            nonce: 0,
            payload: vec![],
            next_auth: H256([0u8; 32]),
            lamport_pk: vec![0u8; PK_LEN - 1],
            sig: vec![0u8; SIG_LEN],
            code: [0u8; 4],
        };
        assert!(HkSignResponse::from_cbor(&resp.to_cbor()).is_err());
        // Three eth-sign-requests the device itself refuses while parsing them: one byte after
        // demo 1, an unknown key on demo 2, version 2.
        let eth = eth_demo(1).to_cbor().unwrap();
        let mut b = eth.clone();
        b.push(0);
        assert!(EthSignRequest::from_cbor(&b).is_err());
        let mut kv = entries(&eth_demo(2).to_cbor().unwrap());
        kv.push(m("memo", Cbor::Text("hi".into())));
        assert!(EthSignRequest::from_cbor(&Cbor::Map(kv).encode()).is_err());
        let mut v2 = eth;
        v2[3] = 0x02;
        assert!(EthSignRequest::from_cbor(&v2).is_err());
        // validate() runs last, after the unknown keys: with an unknown key and net or data out of
        // bounds, the unknown key is the reason (types, fixed lengths and `value` are refused as
        // each field is read, before that). A hint without its symbol is refused as missing.
        let mut kv = entries(&good);
        kv[1].1 = Cbor::Text("n".repeat(41));
        kv.push(m("extra", Cbor::Uint(0)));
        assert!(HkSignRequest::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("unknown key \"extra\""));
        let mut kv = entries(&eth_demo(2).to_cbor().unwrap());
        let at = kv.iter().position(|(k, _)| k == "data").unwrap();
        kv[at].1 = Cbor::Bytes(vec![7; 4097]);
        kv.push(m("extra", Cbor::Uint(0)));
        assert!(EthSignRequest::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("unknown key \"extra\""));
        let mut kv = entries(&good);
        if let Cbor::Map(hint) = &mut kv[5].1 {
            hint.retain(|(k, _)| k != "symbol");
        }
        assert!(HkSignRequest::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("\"symbol\" is missing"));
    }

    /// Every head size class: the boundary values encode shortest and decode back, and each class
    /// refuses a value that fits the class below (`hw_decoding_is_strict` covers ai 24 and 25).
    #[test]
    fn hw_cbor_heads_are_shortest_in_every_size_class() {
        for (v, enc) in [
            (23u64, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (0xffff_ffff, "1affffffff"),
            (1 << 32, "1b0000000100000000"),
            (u64::MAX, "1bffffffffffffffff"),
        ] {
            assert_eq!(hex::encode(Cbor::Uint(v).encode()), enc, "{v}");
            assert_eq!(Cbor::decode(&h(enc)).unwrap(), Cbor::Uint(v), "{v}");
        }
        for wide in ["1817", "1900ff", "190000", "1a0000ffff", "1a00000000", "1b00000000ffffffff", "1b0000000000000000"] {
            assert!(Cbor::decode(&h(wide)).is_err(), "{wide}");
        }
        // The same rule for a length: a 1-byte string with a 4-byte length.
        assert!(Cbor::decode(&h("5a0000000161")).is_err());
    }

    /// What the v1 messages do not use is refused by the decoder itself: ai 28..31, major types
    /// 1/4/6/7, non-text keys, invalid UTF-8, duplicate keys, more than 16 keys.
    #[test]
    fn hw_cbor_refuses_what_the_v1_messages_do_not_use() {
        for b in ["1c", "1d", "1e", "1f", "5f", "7f", "bf", "bfff"] {
            assert!(Cbor::decode(&h(b)).is_err(), "{b}");
        }
        for b in ["20", "80", "c100", "f4", "f5", "f6", "f97c00"] {
            assert!(Cbor::decode(&h(b)).is_err(), "{b}");
        }
        assert!(Cbor::decode(&h("a1016100")).is_err());
        assert!(Cbor::decode(&h("a1416100")).is_err());
        assert_eq!(Cbor::decode(&h("a1616100")).unwrap(), Cbor::Map(vec![m("a", Cbor::Uint(0))]));
        assert!(Cbor::decode(&h("61ff")).is_err());
        assert!(Cbor::decode(&h("a161ff00")).is_err());
        let dup = Cbor::Map(vec![m("a", Cbor::Uint(0)), m("a", Cbor::Uint(1))]).encode();
        assert!(Cbor::decode(&dup).unwrap_err().to_string().contains("duplicate"));
        let mut kv = entries(&demo(NET_TESTNET1, h32(HK_ID)).to_cbor().unwrap());
        kv.push(m("nonce", Cbor::Uint(0)));
        assert!(HkSignRequest::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("duplicate"));
        let map = |n: u64| Cbor::Map((0..n).map(|i| m(&format!("k{i}"), Cbor::Uint(i))).collect()).encode();
        assert!(Cbor::decode(&map(16)).is_ok());
        assert!(Cbor::decode(&map(17)).unwrap_err().to_string().contains("too many keys"));
    }

    /// In all five messages every field but the hint is required, `v` must be 1 and an unknown
    /// key is refused; the same inside both hints. (`hw_decoding_is_strict` covers the two
    /// requests' version and top-level unknown keys, and the HK hint without its symbol.)
    #[test]
    fn hw_every_message_needs_every_field_v1_and_nothing_else() {
        let resp = HkSignResponse {
            sender: H256([0u8; 32]),
            nonce: 0,
            payload: vec![],
            next_auth: H256([0u8; 32]),
            lamport_pk: vec![0u8; PK_LEN],
            sig: vec![0u8; SIG_LEN],
            code: [0u8; 4],
        };
        type Accepts = fn(&[u8]) -> bool;
        let cases: [(&str, Vec<u8>, Accepts); 5] = [
            ("hk-sign-request", demo(NET_TESTNET1, h32(HK_ID)).to_cbor().unwrap(), |b: &[u8]| HkSignRequest::from_cbor(b).is_ok()),
            ("hk-sign-response", resp.to_cbor(), |b: &[u8]| HkSignResponse::from_cbor(b).is_ok()),
            ("hk-pair", h(PAIR), |b: &[u8]| HkPair::from_cbor(b).is_ok()),
            ("eth-sign-request", eth_demo(1).to_cbor().unwrap(), |b: &[u8]| EthSignRequest::from_cbor(b).is_ok()),
            ("eth-sign-response", h(DEMO1_RESP), |b: &[u8]| EthSignResponse::from_cbor(b).is_ok()),
        ];
        let enc = |kv: Vec<(String, Cbor)>| Cbor::Map(kv).encode();
        for (name, good, ok) in cases {
            assert!(ok(&good[..]), "{name}");
            let kv = entries(&good);
            assert_eq!(kv[0].0, "v");
            for i in 0..kv.len() {
                let mut less = kv.clone();
                let (k, _) = less.remove(i);
                assert_eq!(ok(&enc(less)[..]), k == "hint", "{name} without \"{k}\"");
            }
            let mut more = kv.clone();
            more.push(m("zz", Cbor::Uint(0)));
            assert!(!ok(&enc(more)[..]), "{name} with an unknown key");
            for v in [0u64, 2] {
                let mut other = kv.clone();
                other[0].1 = Cbor::Uint(v);
                assert!(!ok(&enc(other)[..]), "{name} v{v}");
            }
            if let Some(hi) = kv.iter().position(|(k, _)| k == "hint") {
                let hkv = match &kv[hi].1 {
                    Cbor::Map(x) => x.clone(),
                    _ => unreachable!(),
                };
                for j in 0..hkv.len() {
                    let mut msg = kv.clone();
                    let mut less = hkv.clone();
                    let (k, _) = less.remove(j);
                    msg[hi].1 = Cbor::Map(less);
                    assert!(!ok(&enc(msg)[..]), "{name} hint without \"{k}\"");
                }
                let mut msg = kv.clone();
                let mut more = hkv.clone();
                more.push(m("zz", Cbor::Uint(0)));
                msg[hi].1 = Cbor::Map(more);
                assert!(!ok(&enc(msg)[..]), "{name} hint with an unknown key");
            }
        }
    }

    /// Diagnostics only: structural refusals that the re-encode equality or `try_into` would also
    /// catch, pinned to their own messages so a lost check shows up as a changed reason.
    #[test]
    fn hw_malformed_bytes_are_refused_for_the_right_reason() {
        let paired = a20(ETH_ADDR);
        let tx = eth_demo(1).tx();
        let raw = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap().raw;
        let why = |b: &[u8]| tx.check_signed(b, &paired).unwrap_err().to_string();
        let mut b = raw.clone();
        b[0] = 0x01;
        assert!(why(&b[..]).contains("type 0x02"));
        let empty: [u8; 0] = [];
        assert!(why(&empty[..]).contains("type 0x02"));
        let mut b = raw.clone();
        b.push(0x00);
        assert!(why(&b[..]).contains("single RLP list"));
        let mut b = raw.clone();
        b[1] = 0xb8;
        assert!(why(&b[..]).contains("single RLP list"));
        let mut b = vec![0x02, 0xf9, 0x00];
        b.extend_from_slice(&raw[2..]);
        assert!(why(&b[..]).contains("shortest form"));
        assert!(why(&[0x02u8, 0xfc, 0x01, 0x00, 0x00, 0x00, 0x00][..]).contains("shortest form"));
        let mut b = vec![0x02u8, 0xf8, 0x37];
        b.extend_from_slice(&[0x80; 0x37]);
        assert!(why(&b[..]).contains("shortest form"));
        assert!(why(&[0x02u8, 0xf8, 0x01, 0x80][..]).contains("shortest form"));
        // A fixed-size CBOR field one byte long is "longer than", one byte short "exactly".
        let mut kv = entries(&h(PAIR));
        assert_eq!(kv[1].0, "id");
        kv[1].1 = Cbor::Bytes(vec![0u8; 33]);
        assert!(HkPair::from_cbor(&Cbor::Map(kv.clone()).encode()).unwrap_err().to_string().contains("longer than 32"));
        kv[1].1 = Cbor::Bytes(vec![0u8; 31]);
        assert!(HkPair::from_cbor(&Cbor::Map(kv).encode()).unwrap_err().to_string().contains("exactly 32"));
    }

    /// Errors are shown on screen as they are, so at both places a key from the wire reaches one
    /// (an unknown key, a key that appears twice), through the pairing decoder and through
    /// `check_eth_response`, a key is named only when it is at most 24 bytes of printable ASCII
    /// without a quote or backslash.
    #[test]
    fn hw_errors_name_a_key_only_when_it_is_safe_to_show() {
        let paired = a20(ETH_ADDR);
        let req = eth_demo(1).to_cbor().unwrap();
        let with_key = |good: &[u8], k: &str| {
            let mut kv = entries(good);
            kv.push(m(k, Cbor::Uint(0)));
            Cbor::Map(kv).encode()
        };
        let twice = |k: &str| Cbor::Map(vec![m(k, Cbor::Uint(0)), m(k, Cbor::Uint(0))]).encode();
        // The device's pairing and its answer to demo 1, each with one more key; then a map that
        // holds the key twice and nothing else.
        let errors = |k: &str| {
            [
                HkPair::from_cbor(&with_key(&h(PAIR), k)).unwrap_err(),
                check_eth_response(&req, &with_key(&h(DEMO1_RESP), k), &paired).unwrap_err(),
                HkPair::from_cbor(&twice(k)).unwrap_err(),
                check_eth_response(&req, &twice(k), &paired).unwrap_err(),
            ]
            .map(|e| e.to_string())
        };
        let fake = "\n\nDevice check passed. It is safe to continue.\r\u{1b}[2J\u{202e}";
        let (k24, k25, long) = ("k".repeat(24), "k".repeat(25), "k".repeat(3000));
        for k in [fake, "me\"mo", "me\\mo", "a\u{7f}b", "a\u{1f}b", "caf\u{e9}", k25.as_str(), long.as_str()] {
            let [unknown, unknown_eth, twice_pair, twice_eth] = errors(k);
            for e in [&unknown, &unknown_eth, &twice_pair, &twice_eth] {
                assert!(!e.contains(['\n', '\r', '\u{1b}', '\u{202e}']) && e.len() < 100, "{e:?}");
            }
            assert_eq!(unknown, "hardware message: a key this wallet does not know");
            assert_eq!(unknown_eth, unknown);
            assert_eq!(twice_pair, "hardware message: a key that appears twice");
            assert_eq!(twice_eth, twice_pair);
        }
        for k in ["memo", "a b~", k24.as_str()] {
            let [unknown, unknown_eth, twice_pair, twice_eth] = errors(k);
            assert_eq!(unknown, format!("hardware message: unknown key \"{k}\""));
            assert_eq!(unknown_eth, unknown);
            assert_eq!(twice_pair, format!("hardware message: duplicate key \"{k}\""));
            assert_eq!(twice_eth, twice_pair);
        }
    }

    /// Every length bound at its edge: net 40, payload 4096 (request and response), symbol 16
    /// (both hints), decimals 18 / 36 (and no wrap into a u8), value at most 32 bytes with no
    /// leading zero on the wire, data 4096, raw 4608, lamport_pk and sig exactly PK_LEN / SIG_LEN.
    #[test]
    fn hw_every_length_bound_is_exact() {
        let hk = demo(NET_TESTNET1, h32(HK_ID));
        assert!(hk_takes(&HkSignRequest { net: "n".repeat(40), ..hk.clone() }));
        assert!(!hk_takes(&HkSignRequest { net: "n".repeat(41), ..hk.clone() }));
        assert!(hk_takes(&HkSignRequest { payload: vec![7; 4096], ..hk.clone() }));
        assert!(!hk_takes(&HkSignRequest { payload: vec![7; 4097], ..hk.clone() }));
        assert!(hk_takes(&HkSignRequest { hint: Some(HkHint { symbol: "S".repeat(16), decimals: 18 }), ..hk.clone() }));
        assert!(!hk_takes(&HkSignRequest { hint: Some(HkHint { symbol: "S".repeat(17), decimals: 6 }), ..hk.clone() }));
        assert!(!hk_takes(&HkSignRequest { hint: Some(HkHint { symbol: "HKN".into(), decimals: 19 }), ..hk.clone() }));
        let resp = HkSignResponse {
            sender: H256([0u8; 32]),
            nonce: 0,
            payload: vec![],
            next_auth: H256([0u8; 32]),
            lamport_pk: vec![0u8; PK_LEN],
            sig: vec![0u8; SIG_LEN],
            code: [0u8; 4],
        };
        let resp_ok = |r: HkSignResponse| HkSignResponse::from_cbor(&r.to_cbor()).is_ok();
        assert!(resp_ok(HkSignResponse { payload: vec![7; 4096], ..resp.clone() }));
        assert!(!resp_ok(HkSignResponse { payload: vec![7; 4097], ..resp.clone() }));
        for (pk, sig) in [(PK_LEN + 1, SIG_LEN), (PK_LEN - 1, SIG_LEN), (PK_LEN, SIG_LEN - 1), (PK_LEN, SIG_LEN + 1)] {
            assert!(!resp_ok(HkSignResponse { lamport_pk: vec![0u8; pk], sig: vec![0u8; sig], ..resp.clone() }), "pk {pk} sig {sig}");
        }
        let e2 = eth_demo(2);
        assert!(eth_takes(&EthSignRequest { value: [0; 32], ..e2.clone() }));
        assert!(eth_takes(&EthSignRequest { value: [0xff; 32], ..e2.clone() }));
        assert!(eth_takes(&EthSignRequest { data: vec![7; 4096], ..e2.clone() }));
        assert!(!eth_takes(&EthSignRequest { data: vec![7; 4097], ..e2.clone() }));
        let usdc = a20(USDC_BASE_SEPOLIA);
        assert!(eth_takes(&EthSignRequest { hint: Some(EthHint { symbol: "S".repeat(16), decimals: 36, contract: usdc }), ..e2.clone() }));
        assert!(!eth_takes(&EthSignRequest { hint: Some(EthHint { symbol: "S".repeat(17), decimals: 6, contract: usdc }), ..e2.clone() }));
        assert!(!eth_takes(&EthSignRequest { hint: Some(EthHint { symbol: "USDC".into(), decimals: 37, contract: usdc }), ..e2.clone() }));
        // `value` on the wire, which the struct holds left-padded: the suite writes it without
        // leading zeros and reads nothing longer than 32 bytes or with a leading zero.
        let with_value = |v: &[u8]| {
            let mut kv = entries(&e2.to_cbor().unwrap());
            let at = kv.iter().position(|(k, _)| k == "value").unwrap();
            kv[at].1 = Cbor::Bytes(v.to_vec());
            EthSignRequest::from_cbor(&Cbor::Map(kv).encode())
        };
        assert_eq!(with_value(&[]).unwrap().value, [0; 32]);
        assert_eq!(with_value(&[1]).unwrap().value, u256(&[1]));
        assert_eq!(with_value(&[0xff; 32]).unwrap().value, [0xff; 32]);
        for bad in [&[0xffu8; 33][..], &[0x00][..], &[0x00, 0x01][..]] {
            assert!(with_value(bad).is_err(), "{bad:02x?}");
        }
        let er = EthSignResponse::from_cbor(&h(DEMO2_RESP)).unwrap();
        let er_ok = |r: EthSignResponse| EthSignResponse::from_cbor(&r.to_cbor()).is_ok();
        assert!(er_ok(EthSignResponse { raw: vec![7; 4096 + 512], ..er.clone() }));
        assert!(!er_ok(EthSignResponse { raw: vec![7; 4096 + 513], ..er.clone() }));
        // Decimals arrive as a CBOR unsigned: 256 and 262 must not wrap to 0 and 6 in a u8.
        let set_decimals = |bytes: Vec<u8>, d: u64| {
            let mut kv = entries(&bytes);
            let hi = kv.iter().position(|(k, _)| k == "hint").unwrap();
            if let Cbor::Map(hkv) = &mut kv[hi].1 {
                let di = hkv.iter().position(|(k, _)| k == "decimals").unwrap();
                hkv[di].1 = Cbor::Uint(d);
            }
            Cbor::Map(kv).encode()
        };
        assert!(HkSignRequest::from_cbor(&set_decimals(hk.to_cbor().unwrap(), 18)).is_ok());
        assert!(EthSignRequest::from_cbor(&set_decimals(eth_demo(1).to_cbor().unwrap(), 36)).is_ok());
        for d in [19u64, 255, 256, 256 + 6] {
            assert!(HkSignRequest::from_cbor(&set_decimals(hk.to_cbor().unwrap(), d)).is_err(), "hk decimals {d}");
        }
        for d in [37u64, 255, 256, 256 + 6] {
            assert!(EthSignRequest::from_cbor(&set_decimals(eth_demo(1).to_cbor().unwrap(), d)).is_err(), "eth decimals {d}");
        }
    }

    /// Every request the suite can hold either encodes and decodes back to itself or is refused
    /// both ways, over a fixed cross product of field values with each bound at its edge: net 40 /
    /// 41 bytes, payload and data 4096 / 4097 bytes, HK symbol 0 / 1 / 16 / 17 bytes, printable
    /// ASCII in net and the HK symbol at both ends (0x20 and 0x7e taken; 0x1f, 0x7f, a newline and
    /// non-ASCII refused), HK decimals 18 / 19, ETH symbol 16 / 17 bytes, ETH decimals 36 / 37,
    /// integers at every CBOR head size, values from 0 to 2^256 - 1. HK decimals 38 and an ETH
    /// symbol of 32 bytes, which the device's parser still takes, are refused here.
    #[test]
    fn hw_requests_round_trip_and_both_directions_refuse_the_same() {
        let uints = [0, 1, 23, 24, 255, 256, 65_535, 65_536, 0xffff_ffff, 1 << 32, u64::MAX];
        let hk = demo(NET_TESTNET1, h32(HK_ID));
        let nets = [
            (NET_TESTNET1.to_string(), true),
            (String::new(), true),
            (" ~".to_string(), true),
            ("n".repeat(40), true),
            ("n".repeat(41), false),
            (format!("{NET_TESTNET1}\n"), false),
            ("net\u{7f}".to_string(), false),
            ("net\u{1f}".to_string(), false),
            ("n\u{e9}t".to_string(), false),
        ];
        let payloads = [(vec![], true), (h(DEMO_PAYLOAD), true), (vec![7u8; 4096], true), (vec![7u8; 4097], false)];
        let hk_hint = |symbol: &str, decimals: u8| Some(HkHint { symbol: symbol.into(), decimals });
        let hk_hints = [
            (None, true),
            (hk_hint("HKN", 6), true),
            (hk_hint("H", 0), true),
            (hk_hint(&"S".repeat(16), 18), true),
            (hk_hint(" ~", 6), true),
            (hk_hint("", 6), false),
            (hk_hint(&"S".repeat(17), 6), false),
            (hk_hint("HKN", 19), false),
            (hk_hint("HKN", 38), false),
            (hk_hint("HKN", 255), false),
            (hk_hint("HK\n", 6), false),
            (hk_hint("HK\u{1f}", 6), false),
            (hk_hint("HK\u{7f}", 6), false),
            (hk_hint("HK\u{e9}", 6), false),
        ];
        for (net, net_ok) in &nets {
            for (payload, payload_ok) in &payloads {
                for (hint, hint_ok) in &hk_hints {
                    for nonce in uints {
                        let r = HkSignRequest { net: net.clone(), nonce, payload: payload.clone(), hint: hint.clone(), ..hk.clone() };
                        assert_eq!(hk_takes(&r), *net_ok && *payload_ok && *hint_ok, "{r:?}");
                    }
                }
            }
        }
        let e1 = eth_demo(1);
        let (usdc, to) = (a20(USDC_BASE_SEPOLIA), a20(DEMO_TO));
        let values = [[0u8; 32], u256(&[1]), u256(&[0x7f]), u256(&[0x80]), u256(&h("2386f26fc10000")), [0x80; 32], [0xff; 32]];
        let datas = [(vec![], true), (vec![0x00], true), (e1.data.clone(), true), (vec![7u8; 4096], true), (vec![7u8; 4097], false)];
        let eth_hint = |symbol: &str, decimals: u8| Some(EthHint { symbol: symbol.into(), decimals, contract: usdc });
        let eth_hints = [
            (None, true),
            (eth_hint("USDC", 6), true),
            (eth_hint("", 0), true),
            (eth_hint(&"S".repeat(16), 36), true),
            (eth_hint("US\nDC", 6), true),
            (eth_hint(&"\u{e9}".repeat(8), 6), true),
            (eth_hint(&"S".repeat(17), 6), false),
            (eth_hint(&"S".repeat(32), 6), false),
            (eth_hint(&"\u{e9}".repeat(9), 6), false),
            (eth_hint("USDC", 37), false),
            (eth_hint("USDC", 255), false),
        ];
        for (i, value) in values.iter().enumerate() {
            for (data, data_ok) in &datas {
                for (hint, hint_ok) in &eth_hints {
                    for j in 0..uints.len() {
                        let u = |k: usize| uints[(j + k) % uints.len()];
                        let r = EthSignRequest {
                            chain_id: u(0),
                            nonce: u(1),
                            max_fee: u(2),
                            max_priority: u(3),
                            gas: u(4),
                            to: if (i + j) % 2 == 0 { to } else { usdc },
                            value: *value,
                            data: data.clone(),
                            hint: hint.clone(),
                            ..e1.clone()
                        };
                        assert_eq!(eth_takes(&r), *data_ok && *hint_ok, "{r:?}");
                    }
                }
            }
        }
    }

    /// The paired address is checked twice, on the request (`from`) and on the signature
    /// (recovery). `hw_eth_checks_refuse_what_was_not_requested` passes another paired address
    /// with `from` = the TEST wallet, which the first check alone refuses.
    #[test]
    fn hw_the_paired_address_is_checked_on_the_request_and_on_the_signature() {
        let paired = a20(ETH_ADDR);
        let other = a20(DEMO_TO);
        let good = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap();
        // A request naming another account, answered with the device's own signature over the same
        // transaction (`from` is not inside the signed bytes), an honest echo and the right code.
        let req = EthSignRequest { from: other, ..eth_demo(1) }.to_cbor().unwrap();
        let mut r = good.clone();
        r.from = other;
        r.code = VerifyCode::of(&req).raw;
        let e = check_eth_response(&req, &r.to_cbor(), &paired).unwrap_err().to_string();
        assert!(e.contains("not from the paired device"), "{e}");
        // Paired with `other`: the request names the paired address, the signature does not.
        let e = check_eth_response(&req, &r.to_cbor(), &other).unwrap_err().to_string();
        assert!(e.contains("not by the paired device") && e.contains(ETH_ADDR), "{e}");
        let tx = eth_demo(1).tx();
        let e = tx.check_signed(&good.raw, &other).unwrap_err().to_string();
        assert!(e.contains("not by the paired device"), "{e}");
        assert_eq!(tx.check_signed(&good.raw, &paired).unwrap(), good.hash);
    }

    /// `chain_id` and `from` in the response are echoes nothing else re-derives, and every byte of
    /// the code and of the hash counts (`hw_eth_checks_refuse_what_was_not_requested` flips byte 0
    /// of each only).
    #[test]
    fn hw_every_response_field_is_bound_to_the_request() {
        let paired = a20(ETH_ADDR);
        let req = eth_demo(1).to_cbor().unwrap();
        let good = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap();
        let refused = |r: &EthSignResponse, why: &str| {
            let e = check_eth_response(&req, &r.to_cbor(), &paired).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        };
        assert!(check_eth_response(&req, &good.to_cbor(), &paired).is_ok());
        let mut r = good.clone();
        r.chain_id = 8453; // the same signed bytes, another chain named in the echo
        refused(&r, "answers another request");
        let mut r = good.clone();
        r.from = a20(DEMO_TO);
        refused(&r, "answers another request");
        let mut r = good.clone();
        r.nonce = 1;
        refused(&r, "answers another request");
        for i in 0..4 {
            let mut r = good.clone();
            r.code[i] ^= 0x80;
            refused(&r, "verification code");
        }
        for i in 0..32 {
            let mut r = good.clone();
            r.hash[i] ^= 0x80;
            refused(&r, "keccak256");
        }
    }

    /// The code covers the request bytes as carried: neither side re-encodes them. The decoder
    /// takes any key order, so a reordered request is accepted, and only its own code answers it.
    #[test]
    fn hw_the_code_covers_the_request_bytes_as_carried() {
        let paired = a20(ETH_ADDR);
        let canonical = eth_demo(1).to_cbor().unwrap();
        let reordered = Cbor::Map(entries(&canonical).into_iter().rev().collect()).encode();
        assert_ne!(reordered, canonical);
        assert_eq!(EthSignRequest::from_cbor(&reordered).unwrap(), eth_demo(1));
        let good = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap();
        let e = check_eth_response(&reordered, &good.to_cbor(), &paired).unwrap_err().to_string();
        assert!(e.contains("verification code"), "{e}");
        let mut r = good.clone();
        r.code = VerifyCode::of(&reordered).raw;
        assert_eq!(check_eth_response(&reordered, &r.to_cbor(), &paired).unwrap(), r);
    }

    /// Malformed `raw` is refused with an error, never a panic: 11 and 13 fields, a 33-byte r or
    /// s, a 2-byte y, missing length bytes, a short payload, r or s zero, r = n. Then two
    /// canonical ones that only the signer and the parity checks refuse.
    #[test]
    fn hw_eth_malformed_raw_is_refused_not_panicked_on() {
        let paired = a20(ETH_ADDR);
        let tx = eth_demo(1).tx();
        let raw = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap().raw;
        let n = raw.len();
        assert_eq!((raw[1], raw[2], raw[n - 67], raw[n - 66], raw[n - 33]), (0xf8, 0xb1, 0x01, 0xa0, 0xa0));
        let refused = |b: &[u8], why: &str| {
            let e = tx.check_signed(b, &paired).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        };
        // 11 fields (s dropped) and 13 (an empty string appended).
        let mut b = raw[..n - 33].to_vec();
        b[2] -= 33;
        refused(&b[..], "twelve fields");
        let mut b = raw.clone();
        b.push(0x80);
        b[2] += 1;
        refused(&b[..], "twelve fields");
        // A 33-byte r and a 33-byte s (a zero byte in front), a 2-byte y.
        let mut b = raw[..n - 66].to_vec();
        b.extend_from_slice(&[0xa1, 0x00]);
        b.extend_from_slice(&raw[n - 65..]);
        b[2] += 1;
        refused(&b[..], "twelve fields");
        let mut b = raw[..n - 33].to_vec();
        b.extend_from_slice(&[0xa1, 0x00]);
        b.extend_from_slice(&raw[n - 32..]);
        b[2] += 1;
        refused(&b[..], "twelve fields");
        let mut b = raw[..n - 67].to_vec();
        b.extend_from_slice(&[0x82, 0x00, 0x01]);
        b.extend_from_slice(&raw[n - 66..]);
        b[2] += 2;
        refused(&b[..], "twelve fields");
        // Truncated: a long-form length without its length bytes, a payload shorter than its head.
        refused(&[0x02u8, 0xf8][..], "RLP length");
        refused(&[0x02u8, 0xb9, 0x01][..], "RLP length");
        refused(&raw[..n - 1], "truncated RLP");
        refused(&[0x02u8, 0xc3, 0x01][..], "truncated RLP");
        // The requested transaction's bytes with r = 0, s = 0, r = n: canonical, but not scalars.
        const N: [u8; 32] = hex_literal(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let rr: [u8; 32] = raw[n - 65..n - 33].try_into().unwrap();
        let ss: [u8; 32] = raw[n - 32..].try_into().unwrap();
        for (r_, s_) in [([0u8; 32], ss), (rr, [0u8; 32]), (N, ss)] {
            refused(&tx.signed(1, &r_, &s_)[..], "out of range");
        }
        // The device's r and s with the other parity: canonical and low s, but they recover
        // another key.
        refused(&tx.signed(0, &rr, &ss)[..], "not by the paired device");
        // A parity-0 signature (demo 1 at nonce 5) written with y = 2.
        let tx5 = EthSignRequest { nonce: 5, ..eth_demo(1) }.tx();
        let raw5 = EthSignResponse::from_cbor(&h(EDGE[0].2)).unwrap().raw;
        let k = raw5.len();
        let r5: [u8; 32] = raw5[k - 65..k - 33].try_into().unwrap();
        let s5: [u8; 32] = raw5[k - 32..].try_into().unwrap();
        let e = tx5.check_signed(&tx5.signed(2, &r5, &s5), &paired).unwrap_err().to_string();
        assert!(e.contains("y parity"), "{e}");
    }

    /// A y parity of 2, 3, 0x7f, 0x80 or 0xff is one byte like 0 and 1 (0x80 and up written 0x81
    /// xx); with `y > 1` unchecked, `RecoveryId::new(y == 1, ..)` would read it as parity 0, and a
    /// y-0 signature would recover the paired key.
    #[test]
    fn hw_a_y_parity_above_one_is_refused() {
        let paired = a20(ETH_ADDR);
        let req = eth_demo(1).to_cbor().unwrap();
        // Demo 1 at nonce 0, hedged, y 0 (written 0x80), 32-byte r and s.
        let good = EthSignResponse::from_cbor(&h(EDGE[6].2)).unwrap();
        assert_eq!(check_eth_response(&req, &good.to_cbor(), &paired).unwrap(), good);
        let n = good.raw.len();
        assert_eq!(good.raw[n - 67], 0x80);
        let rr: [u8; 32] = good.raw[n - 65..n - 33].try_into().unwrap();
        let ss: [u8; 32] = good.raw[n - 32..].try_into().unwrap();
        for y in [2u8, 3, 0x7f, 0x80, 0xff] {
            let mut r = good.clone();
            r.raw = eth_demo(1).tx().signed(y, &rr, &ss);
            r.hash = crate::eth::keccak256(&r.raw);
            let e = check_eth_response(&req, &r.to_cbor(), &paired).unwrap_err().to_string();
            assert!(e.contains("y parity"), "y {y}: {e}");
        }
    }

    /// The EIP-2 bound is exactly (n - 1) / 2: one above is refused as a high s, the bound itself
    /// is not (k256 would refuse a high s too, but with another error).
    #[test]
    fn hw_the_eip2_bound_is_exactly_half_the_group_order() {
        const N: [u8; 32] = hex_literal(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        const HALF: [u8; 32] = hex_literal(b"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        let mut twice_plus_one = [0u8; 32];
        let mut carry = 1u16;
        for i in (0..32).rev() {
            let d = 2 * HALF[i] as u16 + carry;
            twice_plus_one[i] = d as u8;
            carry = d >> 8;
        }
        assert_eq!(twice_plus_one, N);
        let paired = a20(ETH_ADDR);
        let tx = eth_demo(1).tx();
        let raw = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap().raw;
        let n = raw.len();
        let rr: [u8; 32] = raw[n - 65..n - 33].try_into().unwrap();
        let mut above = HALF;
        above[31] += 1;
        let e = tx.check_signed(&tx.signed(1, &rr, &above), &paired).unwrap_err().to_string();
        assert!(e.contains("high s"), "{e}");
        let e = tx.check_signed(&tx.signed(1, &rr, &HALF), &paired).unwrap_err().to_string();
        assert!(!e.contains("high s"), "{e}");
    }

    /// RLP's short and long forms meet where the spec says: a single byte below 0x80 is its own
    /// encoding and 0x80 takes 0x81; 55 bytes take a short head and 56 the long one, for a string
    /// and for the unsigned list the sighash covers.
    #[test]
    fn hw_rlp_short_and_long_forms_meet_where_the_spec_says() {
        let to = a20(DEMO_TO);
        let base = eth_demo(2).tx();
        let after_to = |tx: Eip1559| {
            let b = tx.signed(1, &[1u8; 32], &[1u8; 32]);
            let at = b.windows(21).position(|w| w[0] == 0x94 && w[1..] == to).unwrap() + 21;
            b[at..].to_vec()
        };
        assert!(after_to(Eip1559 { value: u256(&[0x7f]), ..base.clone() }).starts_with(&[0x7f, 0x80, 0xc0]));
        assert!(after_to(Eip1559 { value: u256(&[0x80]), ..base.clone() }).starts_with(&[0x81, 0x80, 0x80, 0xc0]));
        let mut want = vec![0x80u8, 0xb7];
        want.extend_from_slice(&[0x11; 55]);
        want.push(0xc0);
        assert!(after_to(Eip1559 { value: [0; 32], data: vec![0x11; 55], ..base.clone() }).starts_with(&want));
        let mut want = vec![0x80u8, 0xb8, 0x38];
        want.extend_from_slice(&[0x11; 56]);
        want.push(0xc0);
        assert!(after_to(Eip1559 { value: [0; 32], data: vec![0x11; 56], ..base.clone() }).starts_with(&want));
        for (len, head) in [(26usize, vec![0xf7u8]), (27, vec![0xf8, 0x38])] {
            let tx = Eip1559 { chain_id: 1, nonce: 0, max_priority: 0, max_fee: 0, gas: 0, to, value: [0; 32], data: vec![0x11; len] };
            let mut want = vec![0x02];
            want.extend_from_slice(&head);
            want.extend_from_slice(&[0x01, 0x80, 0x80, 0x80, 0x80, 0x94]);
            want.extend_from_slice(&to);
            want.extend_from_slice(&[0x80, 0x80 + len as u8]);
            want.extend_from_slice(&vec![0x11; len]);
            want.push(0xc0);
            assert_eq!(want.len(), 1 + head.len() + 29 + len);
            assert_eq!(tx.sighash(), crate::eth::keccak256(&want), "{len}");
        }
    }

    // The device's answers to demo 2 and demo 1 at nonce 0 sent with the value zero-padded to 32
    // bytes, bytes the suite never writes (from its reference vectors for the TEST wallet).
    const PADDED: [(u8, &str, &str); 2] = [
        (2, "aa61760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e636500676d61785f6665651a05f5e1006c6d61785f7072696f726974791a000f42406367617319520862746f549858effd232b4033e47d90003d41ec34ecaeda946576616c75655820000000000000000000000000000000000000000000000000002386f26fc10000646461746140", "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e63650063726177587602f87383014a3480830f42408405f5e100825208949858effd232b4033e47d90003d41ec34ecaeda94872386f26fc1000080c001a0064c85062682c74348eb44418018e2871b1ee0fd0a5189e01ad4a035af167165a00221b3fae3f915bc752deb2ecb312fe1e34b738545c4ac9d4108071a0117c71c646861736858200fbb52e73954b6f4981ce3a9a14f1aeee721b28d9f33e77c23dd000a8b45aeba64636f646544c46ccc08"),
        (1, "ab61760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e636500676d61785f6665651a05f5e1006c6d61785f7072696f726974791a000f42406367617319fde862746f54036cbd53842c5426634e7929541ec2318f3dcf7e6576616c75655820000000000000000000000000000000000000000000000000000000000000000064646174615844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc206468696e74a36673796d626f6c645553444368646563696d616c730668636f6e747261637454036cbd53842c5426634e7929541ec2318f3dcf7e", "a761760168636861696e5f69641a00014a346466726f6d5429458c602e3db4fc3b54ec2bbee26dbe64c7779f656e6f6e6365006372617758b402f8b183014a3480830f42408405f5e10082fde894036cbd53842c5426634e7929541ec2318f3dcf7e80b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000000000000000000000000000000000000000bebc20c001a0fff4f4463f487fc065eda80dd6fd17bceb3da4313a916f2d1ab7c95339ab2391a0250de4538a48169ee47566fbd673f1443d3c2326da6fa97441a7eb5def72367564686173685820b5679831534d7ce721bf0f8f53a48ca458552d71ba5be39e85889c7dfeac763e64636f646544bc82a7cd"),
    ];

    /// The device strips a zero-padded value and signs its demo's own transaction; the suite
    /// refuses to read the padded request, so it refuses the answer too, although the signed
    /// bytes check out against the canonical request.
    #[test]
    fn hw_eth_padded_values_are_refused_though_the_device_signs_the_canonical_tx() {
        let paired = a20(ETH_ADDR);
        for (which, req, resp) in PADDED {
            let (req, resp) = (h(req), h(resp));
            let canonical = eth_demo(which);
            // The padded request is ours with `value` written as all 32 bytes.
            let mut kv = entries(&canonical.to_cbor().unwrap());
            let at = kv.iter().position(|(k, _)| k == "value").unwrap();
            kv[at].1 = Cbor::Bytes(canonical.value.to_vec());
            assert_eq!(Cbor::Map(kv).encode(), req);
            for e in [EthSignRequest::from_cbor(&req).unwrap_err(), check_eth_response(&req, &resp, &paired).unwrap_err()] {
                assert!(e.to_string().contains("\"value\" has a leading zero byte"), "{e}");
            }
            // The same raw and hash as the device's answer to the canonical request: only the
            // code, over the padded bytes, differs.
            let back = EthSignResponse::from_cbor(&resp).unwrap();
            assert_eq!(canonical.tx().check_signed(&back.raw, &paired).unwrap(), back.hash);
            let demo = EthSignResponse::from_cbor(&h(if which == 1 { DEMO1_RESP } else { DEMO2_RESP })).unwrap();
            assert_eq!(EthSignResponse { code: demo.code, ..back.clone() }, demo);
            assert_eq!(back.code, VerifyCode::of(&req).raw);
            assert_ne!(back.code, demo.code);
        }
    }

    // Reference signatures for boundary cases, from the device's reference model of secp256k1,
    // Keccak-256 and RLP (independent of k256); each signer's address was derived or recovered
    // there, and no key is kept here. (case, transaction, signed bytes, signer)
    const REF: [(&str, usize, &str, &str); 14] = [
        ("32-byte r and s", 0, "02f864017f818081ff8201009400000000000000000000000000000000000000007f00c001a0eea9061bd4187cd3fd7a8620238fbdce28aad3d335e24fe634b79ef98e5afcada01ecb16d8c2707e35f75458f3f374f09efae7bd0191eade0b10a6b6cf2239bfae", "ba9a241aeeedc5e8199e389cab4f1c1b8cda3d00"),
        ("s = n/2", 0, "02f864017f818081ff8201009400000000000000000000000000000000000000007f00c080a041f094028c7cd36c4ed3029eb9f6aa927941b09e4f6da497abe1f73f1c9ea72ea07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "66ab0ebaa73c455256853491179ea1723bf4ab45"),
        ("s = n/2 + 1", 0, "02f864017f818081ff8201009400000000000000000000000000000000000000007f00c080a041f094028c7cd36c4ed3029eb9f6aa927941b09e4f6da497abe1f73f1c9ea72ea07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", "82d8d036fa6d10608792900f9709ade561cd9f01"),
        ("its low twin", 0, "02f864017f818081ff8201009400000000000000000000000000000000000000007f00c001a041f094028c7cd36c4ed3029eb9f6aa927941b09e4f6da497abe1f73f1c9ea72ea07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "82d8d036fa6d10608792900f9709ade561cd9f01"),
        ("r 1, s 1, y 0", 0, "02e4017f818081ff8201009400000000000000000000000000000000000000007f00c0800101", "9be7301d69143161ab4328a5c5e86fff7a9724c0"),
        ("r 1, s 1, y 1", 1, "02ec82210501830f42408405f5e10082520894000000000000000000000000000000000000000081807fc0010101", "19f0fd28e90c68c64224cfdc177533f92c6f4004"),
        ("r 1, s 0x80, y 0", 0, "02e5017f818081ff8201009400000000000000000000000000000000000000007f00c080018180", "2103295dfb5a14cf279d1265b1e3a3584556bdec"),
        ("r 1, s 0x80, y 1", 1, "02ed82210501830f42408405f5e10082520894000000000000000000000000000000000000000081807fc001018180", "22dbb6d2790ce06fc846a8f7f1aaa93ff669661f"),
        ("r 0x81, s 0x7f, y 0", 0, "02e5017f818081ff8201009400000000000000000000000000000000000000007f00c08081817f", "f27eb385a8cf242689267abc36c3d1b2f2c3f717"),
        ("r 0x81, s 0x7f, y 1", 1, "02ed82210501830f42408405f5e10082520894000000000000000000000000000000000000000081807fc00181817f", "7aed73e5aa5998a185a4b41d2310e21dac851ea5"),
        ("r 0x81, s n/2, y 0", 0, "02f845017f818081ff8201009400000000000000000000000000000000000000007f00c0808181a07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "56a4afbfda7eac590023a0a89359241d16d8aeb7"),
        ("r 0x81, s n/2, y 1", 1, "02f84d82210501830f42408405f5e10082520894000000000000000000000000000000000000000081807fc0018181a07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "f4ac2e9ecc1200be190b2ef091ec1efb42212e85"),
        ("x-reduced, r 2, y 0", 2, "02f86783aa36a705830f42408405f5e10082520894000000000000000000000000000000000000000001b7809101783bf3e4ac84d8d48720a42bcb43e9bb61bc0cf7a2986587c4ccd1edf85a2836a57b3d5aace52d0e543e74a855ad5b59534e20c0c080028401234567", "4acefa29fcfe3356a25f11c50be7a09bed05ec1d"),
        ("x-reduced, r 2, y 1", 2, "02f86783aa36a705830f42408405f5e10082520894000000000000000000000000000000000000000001b7809101783bf3e4ac84d8d48720a42bcb43e9bb61bc0cf7a2986587c4ccd1edf85a2836a57b3d5aace52d0e543e74a855ad5b59534e20c0c001028401234567", "f1e1f45ae7deb549820ba3f008cc0c42f0d08792"),
    ];

    /// The reference's transactions and signing hashes: single bytes 0x7f / 0x80 / 0xff / 0x100,
    /// value 0x7f and data 0x00 on chain 1; value 0x80 and data 0x7f on chain 8453; value 1 and 55
    /// bytes of data on chain 11155111.
    fn ref_tx(i: usize) -> (Eip1559, &'static str) {
        let to = [0u8; 20];
        match i {
            0 => (Eip1559 { chain_id: 1, nonce: 127, max_priority: 128, max_fee: 255, gas: 256, to, value: u256(&[0x7f]), data: vec![0x00] }, "5f6ec6d8ab3d09871181871a17db7c6751482f6de335cba745f0f954cc5a7302"),
            1 => (Eip1559 { chain_id: 8453, nonce: 1, max_priority: 1_000_000, max_fee: 100_000_000, gas: 21_000, to, value: u256(&[0x80]), data: vec![0x7f] }, "30298a97f502a35eb9aed2032de7057f7acbb31cd1d5b499c8bfa53422804add"),
            _ => (
                Eip1559 { chain_id: 11_155_111, nonce: 5, max_priority: 1_000_000, max_fee: 100_000_000, gas: 21_000, to, value: u256(&[1]), data: h("809101783bf3e4ac84d8d48720a42bcb43e9bb61bc0cf7a2986587c4ccd1edf85a2836a57b3d5aace52d0e543e74a855ad5b59534e20c0") },
                "35e8ef4527d6d239e1964571720b7d07dac04b533d614d6eb2cbd2bd63308dfd",
            ),
        }
    }

    /// One reference case: its transaction (whose signing hash must be the reference's), its
    /// signed bytes and its signer.
    fn reference(case: &str) -> (Eip1559, Vec<u8>, [u8; 20]) {
        let &(_, i, raw, signer) = REF.iter().find(|c| c.0 == case).unwrap();
        let (tx, sighash) = ref_tx(i);
        assert_eq!(hex::encode(tx.sighash()), sighash, "{case}");
        (tx, h(raw), a20(signer))
    }

    /// EIP-2's bound on the reference's signatures: s = floor(n/2) is accepted, floor(n/2) + 1 is
    /// refused as a high s, and that signature's low twin (n - s = floor(n/2), the parity flipped)
    /// is accepted.
    #[test]
    fn hw_eth_low_s_boundary() {
        for (case, s_last, ok) in [("s = n/2", 0xa0, true), ("s = n/2 + 1", 0xa1, false), ("its low twin", 0xa0, true)] {
            let (tx, raw, signer) = reference(case);
            let n = raw.len();
            assert_eq!(hex::encode(&raw[n - 32..]), format!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20{s_last:02x}"));
            match tx.check_signed(&raw, &signer) {
                Ok(hash) => assert!(ok && hash == crate::eth::keccak256(&raw), "{case}"),
                Err(e) => assert!(!ok && e.to_string().contains("high s"), "{case}: {e}"),
            }
        }
    }

    /// A signature whose R has an x of n or more verifies, but an EIP-1559 y parity cannot say so:
    /// recovered with r as x it gives another key, and the suite refuses it. The reference's two
    /// are genuine: k256 recovers their signer when told x was reduced.
    #[test]
    fn hw_eth_x_reduced_is_refused() {
        for (case, y) in [("x-reduced, r 2, y 0", 0u8), ("x-reduced, r 2, y 1", 1)] {
            let (tx, raw, signer) = reference(case);
            let e = tx.check_signed(&raw, &signer).unwrap_err().to_string();
            assert!(e.contains("not by the paired device"), "{case}: {e}");
            // y, then r = 2 and s = 0x1234567 close the list.
            let n = raw.len();
            assert_eq!(&raw[n - 7..], &[[0x80u8, 0x01][y as usize], 0x02, 0x84, 0x01, 0x23, 0x45, 0x67]);
            let sig = Signature::from_scalars(u256(&[2]), u256(&[0x01, 0x23, 0x45, 0x67])).unwrap();
            let vk = VerifyingKey::recover_from_prehash(&tx.sighash(), &sig, RecoveryId::new(y == 1, true)).unwrap();
            assert_eq!(crate::eth::address_of(&vk), signer, "{case}");
        }
    }

    /// Canonical RLP is the only encoding accepted. The reference's short forms pass: r and s of
    /// one byte, below 0x80 as itself and from 0x80 as 0x81 xx, and a 1-byte r beside a 32-byte s.
    /// Every other encoding of the same values is refused: outer lengths with a leading zero, in 4
    /// or 5 bytes, or in the long form for 55 bytes or fewer; 11 and 13 items; a non-empty access
    /// list; an empty `to`; a leading zero in the chain id or the nonce; y, r or s written longer.
    #[test]
    fn hw_eth_noncanonical_rlp_is_refused() {
        for case in [
            "32-byte r and s",
            "r 1, s 1, y 0",
            "r 1, s 1, y 1",
            "r 1, s 0x80, y 0",
            "r 1, s 0x80, y 1",
            "r 0x81, s 0x7f, y 0",
            "r 0x81, s 0x7f, y 1",
            "r 0x81, s n/2, y 0",
            "r 0x81, s n/2, y 1",
        ] {
            let (tx, raw, signer) = reference(case);
            assert_eq!(tx.check_signed(&raw, &signer).unwrap(), crate::eth::keccak256(&raw), "{case}");
        }
        let refused = |tx: &Eip1559, signer: &[u8; 20], b: &[u8], why: &str| {
            let e = tx.check_signed(b, signer).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        };
        // 0x02 and a canonical list head around `body` with its bytes `at` replaced by `by`.
        let relist = |body: &[u8], at: std::ops::Range<usize>, by: &[u8]| {
            let mut body = body.to_vec();
            body.splice(at, by.iter().copied());
            let mut b = vec![0x02];
            match body.len() {
                n @ 0..=55 => b.push(0xc0 + n as u8),
                n => b.extend_from_slice(&[0xf8, n as u8]),
            }
            b.extend_from_slice(&body);
            b
        };
        // f8 64, then: chain id 01, nonce 7f, 81 80, 81 ff, 82 01 00, `to` 94 and 20 bytes, value
        // 7f, data 00, access list c0, y 01, r a0 and 32 bytes, s a0 and 32 bytes.
        let (tx, raw, signer) = reference("32-byte r and s");
        let body = &raw[3..];
        assert_eq!((&raw[..3], body.len(), body[9], body[32], body[33]), (&[0x02u8, 0xf8, 0x64][..], 100, 0x94, 0xc0, 0x01));
        assert_eq!(relist(body, 0..0, &[]), raw);
        refused(&tx, &signer, &[&[0x02u8, 0xf9, 0x00, 0x64][..], body].concat(), "shortest form");
        refused(&tx, &signer, &[&[0x02u8, 0xfb, 0x00, 0x00, 0x00, 0x64][..], body].concat(), "shortest form");
        refused(&tx, &signer, &[&[0x02u8, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x64][..], body].concat(), "too long");
        refused(&tx, &signer, &relist(body, 67..100, &[]), "twelve fields");
        refused(&tx, &signer, &relist(body, 100..100, &[0x80]), "twelve fields");
        refused(&tx, &signer, &relist(body, 34..35, &[0xa1, 0x00]), "twelve fields");
        for (at, by) in [(32..33, &[0xc1u8, 0x80][..]), (9..30, &[0x80][..]), (0..1, &[0x82, 0x00, 0x01][..]), (1..2, &[0x82, 0x00, 0x7f][..]), (33..34, &[0x81, 0x01][..])] {
            refused(&tx, &signer, &relist(body, at, by), "not the requested transaction");
        }
        // e4, then the same nine fields, y 80, r 01, s 01.
        let (tx, raw, signer) = reference("r 1, s 1, y 0");
        let body = &raw[2..];
        assert_eq!((raw[1], body.len(), &body[33..]), (0xe4, 36, &[0x80u8, 0x01, 0x01][..]));
        refused(&tx, &signer, &[&[0x02u8, 0xf8, 0x24][..], body].concat(), "shortest form");
        let mut one = vec![0xa0];
        one.extend_from_slice(&u256(&[1]));
        for (at, by) in [(33..34, &[0x00u8][..]), (34..35, &[0x81, 0x01][..]), (35..36, &[0x81, 0x01][..]), (34..35, &one[..]), (35..36, &one[..])] {
            refused(&tx, &signer, &relist(body, at, by), "not the requested transaction");
        }
    }

    /// No prefix, no trailing byte and no flipped bit (or 0xff mask) in any byte turns a signed
    /// transaction into one the suite accepts, or makes the check panic: the reference's 32-byte
    /// and 1-byte signatures and the device's answer to demo 1.
    #[test]
    fn hw_eth_truncations_and_bit_flips_never_pass() {
        let (t0, raw0, signer0) = reference("32-byte r and s");
        let (t1, raw1, signer1) = reference("r 1, s 1, y 0");
        let demo = EthSignResponse::from_cbor(&h(DEMO1_RESP)).unwrap().raw;
        for (tx, raw, signer) in [(t0, raw0, signer0), (t1, raw1, signer1), (eth_demo(1).tx(), demo, a20(ETH_ADDR))] {
            assert_eq!(tx.check_signed(&raw, &signer).unwrap(), crate::eth::keccak256(&raw));
            for n in 0..raw.len() {
                assert!(tx.check_signed(&raw[..n], &signer).is_err(), "the first {n} bytes");
            }
            for b in [0x00u8, 0x80, 0xc0] {
                assert!(tx.check_signed(&[&raw[..], &[b][..]].concat(), &signer).is_err(), "trailing {b:02x}");
            }
            for i in 0..raw.len() {
                for mask in [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff] {
                    let mut x = raw.clone();
                    x[i] ^= mask;
                    assert!(tx.check_signed(&x, &signer).is_err(), "byte {i} ^ {mask:02x}");
                }
            }
        }
    }
}
