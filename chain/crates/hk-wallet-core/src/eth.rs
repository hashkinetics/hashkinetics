//! Ethereum transactions as the suite needs them for the hardware signer: the EIP-1559 (type
//! 0x02) transaction with an empty access list, its RLP and signing hash, and the check on a
//! signed one. The core holds no secp256k1 private key: the device signs, and it hedges its
//! ECDSA nonces with RNG bytes, so a signature is checked by decoding and recovery, never by
//! comparing it with an expected one. JSON-RPC (balances, fees, broadcast) is not part of this
//! module.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::WalletError;

pub fn keccak256(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

/// The Ethereum address of an uncompressed secp256k1 public key.
pub fn address_of(vk: &VerifyingKey) -> [u8; 20] {
    let p = vk.to_encoded_point(false);
    keccak256(&p.as_bytes()[1..])[12..].try_into().unwrap()
}

/// n / 2 for secp256k1: a signature's s must not be above it (EIP-2).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
    0x68, 0x1b, 0x20, 0xa0,
];

fn err(m: impl std::fmt::Display) -> WalletError {
    WalletError::msg(format!("Ethereum transaction: {m}"))
}

// ---- RLP (what a type-0x02 transaction needs) ----

/// Big-endian with no leading zeros: RLP's integer form (zero is the empty string).
pub fn be_min(b: &[u8]) -> &[u8] {
    let z = b.iter().take_while(|&&x| x == 0).count();
    &b[z..]
}

fn rlp_head(out: &mut Vec<u8>, n: usize, off: u8) {
    if n <= 55 {
        out.push(off + n as u8);
    } else {
        let be = (n as u64).to_be_bytes();
        let be = be_min(&be);
        out.push(off + 55 + be.len() as u8);
        out.extend_from_slice(be);
    }
}

fn rlp_bytes(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_head(out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
}

fn rlp_uint(out: &mut Vec<u8>, v: u64) {
    rlp_bytes(out, be_min(&v.to_be_bytes()));
}

fn rlp_list(items: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() + 9);
    rlp_head(&mut out, items.len(), 0xc0);
    out.extend_from_slice(items);
    out
}

/// One RLP item's payload: `(is_list, payload, rest)`. Lengths must be in their shortest form;
/// whether the bytes are canonical as a whole is settled by re-encoding (see `check_signed`).
fn rlp_item(b: &[u8]) -> Result<(bool, &[u8], &[u8]), WalletError> {
    let (&h, rest) = b.split_first().ok_or_else(|| err("truncated RLP"))?;
    let (list, len, rest) = match h {
        0x00..=0x7f => return Ok((false, &b[..1], rest)),
        0x80..=0xb7 => (false, (h - 0x80) as usize, rest),
        0xc0..=0xf7 => (true, (h - 0xc0) as usize, rest),
        _ => {
            let (list, n) = if h >= 0xf8 { (true, (h - 0xf7) as usize) } else { (false, (h - 0xb7) as usize) };
            if n > 4 || rest.len() < n || rest[0] == 0 {
                return Err(err("an RLP length that is too long or not in its shortest form"));
            }
            let len = rest[..n].iter().fold(0usize, |a, &x| a << 8 | x as usize);
            if len <= 55 {
                return Err(err("an RLP length that is not in its shortest form"));
            }
            (list, len, &rest[n..])
        }
    };
    if rest.len() < len {
        return Err(err("truncated RLP"));
    }
    Ok((list, &rest[..len], &rest[len..]))
}

/// An unsigned EIP-1559 transaction with an empty access list: what the device is asked to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority: u64,
    pub max_fee: u64,
    pub gas: u64,
    pub to: [u8; 20],
    /// Wei, a uint256, big-endian.
    pub value: [u8; 32],
    pub data: Vec<u8>,
}

impl Eip1559 {
    /// The nine unsigned fields, each RLP-encoded, back to back.
    fn fields(&self) -> Vec<u8> {
        let mut f = Vec::new();
        rlp_uint(&mut f, self.chain_id);
        rlp_uint(&mut f, self.nonce);
        rlp_uint(&mut f, self.max_priority);
        rlp_uint(&mut f, self.max_fee);
        rlp_uint(&mut f, self.gas);
        rlp_bytes(&mut f, &self.to);
        rlp_bytes(&mut f, be_min(&self.value));
        rlp_bytes(&mut f, &self.data);
        f.push(0xc0); // the empty access list
        f
    }

    /// keccak256(0x02 ‖ rlp([nine fields])): the hash the signature covers.
    pub fn sighash(&self) -> [u8; 32] {
        let mut b = vec![0x02];
        b.extend_from_slice(&rlp_list(&self.fields()));
        keccak256(&b)
    }

    /// 0x02 ‖ rlp([nine fields, y parity, r, s]): the bytes that are broadcast.
    pub fn signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut f = self.fields();
        rlp_uint(&mut f, y_parity as u64);
        rlp_bytes(&mut f, be_min(r));
        rlp_bytes(&mut f, be_min(s));
        let mut b = vec![0x02];
        b.extend_from_slice(&rlp_list(&f));
        b
    }

    /// The suite's check of a device's signed transaction: `raw` must be exactly THIS
    /// transaction (every field as requested, canonical RLP), with a low s, signed by `signer`.
    /// Returns the transaction hash, keccak256(raw).
    pub fn check_signed(&self, raw: &[u8], signer: &[u8; 20]) -> Result<[u8; 32], WalletError> {
        let body = match raw.split_first() {
            Some((0x02, b)) => b,
            _ => return Err(err("not an EIP-1559 (type 0x02) transaction")),
        };
        let (list, items, rest) = rlp_item(body)?;
        if !list || !rest.is_empty() {
            return Err(err("not a single RLP list"));
        }
        let mut it = items;
        let mut parts: Vec<&[u8]> = Vec::new();
        while !it.is_empty() {
            let (_, p, r) = rlp_item(it)?;
            parts.push(p);
            it = r;
        }
        if parts.len() != 12 || parts[9].len() > 1 || parts[10].len() > 32 || parts[11].len() > 32 {
            return Err(err("not the twelve fields of a signed transaction"));
        }
        let y = parts[9].first().copied().unwrap_or(0);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r[32 - parts[10].len()..].copy_from_slice(parts[10]);
        s[32 - parts[11].len()..].copy_from_slice(parts[11]);
        if y > 1 {
            return Err(err("a y parity other than 0 or 1"));
        }
        // Re-encoding the REQUESTED fields with this signature must give the same bytes: every
        // field is as requested and the encoding is canonical.
        if self.signed(y, &r, &s) != raw {
            return Err(err("the signed bytes are not the requested transaction"));
        }
        if s > HALF_N {
            return Err(err("a high s (EIP-2 refuses it)"));
        }
        let sig = Signature::from_scalars(r, s).map_err(|_| err("r or s out of range"))?;
        let h = self.sighash();
        // In k256 0.13 recovery already verifies the signature against the key it recovers, low s
        // included, so the verify after it is a second check that cannot fail on its own.
        let vk = VerifyingKey::recover_from_prehash(&h, &sig, RecoveryId::new(y == 1, false)).map_err(|_| err("no signer can be recovered"))?;
        vk.verify_prehash(&h, &sig).map_err(|_| err("the signature does not verify"))?;
        if address_of(&vk) != *signer {
            return Err(err(format!("signed by 0x{}, not by the paired device", hex::encode(address_of(&vk)))));
        }
        Ok(keccak256(raw))
    }
}
