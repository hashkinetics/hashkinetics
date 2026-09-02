//! THE P0 STORYLINE, AS A TEST. This is the demo script in executable form:
//! $50 org mandate → 3 agents (oversubscribed) → one overspends → rejected →
//! revoke kills the subtree → 1,000 paid API calls settle through one PayWord word →
//! replay + tampered signatures rejected → two nodes replaying the same blocks reach
//! the identical state commitment (the determinism consensus needs).

use crate::tx::{signing_digest, SignedTx, Tx};
use crate::{Genesis, GenesisAccount, GenesisFee, State};
use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_crypto::lamport;
use hk_crypto::payword::PaywordChain;
use hk_primitives::{Amount, H256};

fn h(b: u8) -> H256 {
    H256([b; 32])
}

/// Test-side wallet: derives the whole L-ratchet chain from a seed.
/// NOTE (Lamport hygiene): if a tx is REJECTED on-chain, the wallet must roll back
/// its local nonce to retry — re-signing a DIFFERENT payload at the same index leaks
/// additional OTS chunks. Acceptable on devnet, forbidden in production wallets
/// (production keys are XMSS/LMS multi-use anyway).
struct Keychain {
    id: H256,
    seed: Vec<u8>,
    next_nonce: u64,
}

impl Keychain {
    fn new(name: &[u8]) -> Self {
        Self {
            id: H256(shake256_32(DOM_ACCOUNT_ID, &[name])),
            seed: name.to_vec(),
            next_nonce: 0,
        }
    }
    fn commit_at(&self, nonce: u64) -> H256 {
        let (_, pk) = lamport::keygen(&self.seed, nonce);
        H256(lamport::pk_commit(&pk))
    }
    fn genesis(&self) -> GenesisAccount {
        GenesisAccount { id: self.id, auth_commit: self.commit_at(0) }
    }
    fn sign(&mut self, payload: Tx) -> SignedTx {
        let nonce = self.next_nonce;
        let (sk, pk) = lamport::keygen(&self.seed, nonce);
        let next_auth = self.commit_at(nonce + 1);
        let digest = signing_digest(&payload, &self.id, nonce, &next_auth).unwrap();
        let sig = lamport::sign(&sk, &digest);
        self.next_nonce += 1;
        SignedTx { sender: self.id, nonce, payload, next_auth, lamport_pk: pk, sig }
    }
    /// Local rollback after an on-chain rejection.
    fn rollback(&mut self) {
        self.next_nonce -= 1;
    }
}

#[test]
fn p0_demo_storyline() {
    const M: Amount = 1_000_000; // $1 in micro-units
    let usd = h(9);
    let mut org = Keychain::new(b"org");
    let mut a = Keychain::new(b"agent-a");
    let mut b = Keychain::new(b"agent-b");
    let mut c = Keychain::new(b"agent-c");
    let mut merchant = Keychain::new(b"merchant");

    let genesis = Genesis {
        time: 1_000,
        accounts: vec![org.genesis(), a.genesis(), b.genesis(), c.genesis(), merchant.genesis()],
        alloc: vec![(org.id, usd, 50 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();

    let (m0, ma, mb, mc) = (h(0xA0), h(0xA1), h(0xA2), h(0xA3));
    let expiry = 1_000_000u64;

    // ---- Block 1: org builds the tree. Kids oversubscribe: 20+25+20 = 65 > 50 root.
    let mk = |id, parent, holder, buffer_max, per_tx, initial, tier| Tx::MandateCreate {
        id,
        parent,
        holder,
        asset: usd,
        rate_per_sec: 0,
        buffer_max,
        per_tx_max: per_tx,
        initial_buffer: initial,
        expiry,
        tier,
    };
    let txs1 = vec![
        org.sign(mk(m0, None, org.id, 50 * M, 50 * M, 50 * M, 2)),
        org.sign(mk(ma, Some(m0), a.id, 20 * M, 20 * M, 20 * M, 0)),
        org.sign(mk(mb, Some(m0), b.id, 25 * M, 20 * M, 25 * M, 0)),
        org.sign(mk(mc, Some(m0), c.id, 20 * M, 20 * M, 20 * M, 0)),
    ];
    let r1 = st.apply_block(1, 1_010, &txs1).unwrap();
    assert!(r1.iter().all(|r| r.result.is_ok()), "{r1:?}");

    // ---- Block 2: A pays 20, B pays 20, C tries 20 → root envelope has only 10 left.
    let txs2 = vec![
        a.sign(Tx::MandateSpend { leaf: ma, to: merchant.id, amount: 20 * M }),
        b.sign(Tx::MandateSpend { leaf: mb, to: merchant.id, amount: 20 * M }),
        c.sign(Tx::MandateSpend { leaf: mc, to: merchant.id, amount: 20 * M }),
    ];
    let r2 = st.apply_block(2, 1_020, &txs2).unwrap();
    assert!(r2[0].result.is_ok());
    assert!(r2[1].result.is_ok());
    let overspend_err = r2[2].result.as_ref().unwrap_err();
    assert!(overspend_err.contains("insufficient buffer at depth 1"), "got: {overspend_err}");
    c.rollback(); // wallet-side: rejected tx didn't consume the on-chain nonce
    assert_eq!(st.balance(&org.id, &usd), 10 * M);
    assert_eq!(st.balance(&merchant.id, &usd), 40 * M);

    // ---- Block 3: revoke C's mandate; B opens a 1,000-call PayWord channel; merchant
    //      settles all 1,000 calls with ONE 32-byte word; C tries again → revoked.
    let chain = PaywordChain::mint(b"payword-seed", b"demo-session", 1_000);
    let tip = H256(chain.tip());
    let ch_id = State::derive_channel_id(&b.id, &merchant.id, &tip, 1); // b's on-chain nonce is 1
    let txs3 = vec![
        org.sign(Tx::MandateRevoke { target: mc }),
        b.sign(Tx::ChannelOpen {
            id: ch_id,
            mandate: mb,
            payee: merchant.id,
            asset: usd,
            tip,
            unit_price: 5_000,      // half a cent per call
            max_steps: 1_000,       // escrow = 5_000 × 1_000 = 5M = B's remaining buffer
            expiry: 900_000,
        }),
        merchant.sign(Tx::ChannelSettle { id: ch_id, word: H256(chain.pay(1_000).unwrap()), step: 1_000 }),
        c.sign(Tx::MandateSpend { leaf: mc, to: merchant.id, amount: M }),
    ];
    let r3 = st.apply_block(3, 1_030, &txs3).unwrap();
    assert!(r3[0].result.is_ok(), "{:?}", r3[0]);
    assert!(r3[1].result.is_ok(), "{:?}", r3[1]);
    assert!(r3[2].result.is_ok(), "{:?}", r3[2]);
    let revoked_err = r3[3].result.as_ref().unwrap_err();
    assert!(revoked_err.contains("revoked at depth 0"), "got: {revoked_err}");
    c.rollback();

    let ch = st.channels.get(&ch_id).unwrap();
    assert_eq!(ch.escrow_remaining, 0);
    assert_eq!(ch.state.highest_step_settled, 1_000);
    assert_eq!(st.balance(&org.id, &usd), 5 * M); // 50 − 20 − 20 − 5 escrow
    assert_eq!(st.balance(&merchant.id, &usd), 45 * M); // 20 + 20 + 5 settled

    // ---- Block 4: replay and forgery are rejected.
    let mut tampered = org.sign(Tx::Transfer { to: a.id, asset: usd, amount: M });
    tampered.sig[100] ^= 1;
    let txs4 = vec![
        txs2[0].clone(), // replay A's already-executed spend
        tampered,
    ];
    let r4 = st.apply_block(4, 1_040, &txs4).unwrap();
    let replay_err = r4[0].result.as_ref().unwrap_err();
    assert!(replay_err.contains("bad nonce"), "got: {replay_err}");
    let forge_err = r4[1].result.as_ref().unwrap_err();
    assert!(forge_err.contains("bad signature"), "got: {forge_err}");
    org.rollback();

    // ---- Determinism: a second node replaying the same blocks reaches the SAME
    //      commitment — this is the property consensus certifies.
    let mut st2 = State::from_genesis(&genesis).unwrap();
    st2.apply_block(1, 1_010, &txs1).unwrap();
    st2.apply_block(2, 1_020, &txs2).unwrap();
    st2.apply_block(3, 1_030, &txs3).unwrap();
    st2.apply_block(4, 1_040, &txs4).unwrap();
    assert_eq!(st.state_commitment(), st2.state_commitment());
}

#[test]
fn channel_refund_after_expiry() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"org2");
    let mut merchant = Keychain::new(b"merchant2");
    let genesis = Genesis {
        time: 100,
        accounts: vec![org.genesis(), merchant.genesis()],
        alloc: vec![(org.id, usd, 10 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();

    let m0 = h(0xB0);
    let chain = PaywordChain::mint(b"s", b"ctx", 100);
    let tip = H256(chain.tip());

    // org holds the root mandate itself and opens a channel under it (nonce 1).
    let ch_id = State::derive_channel_id(&org.id, &merchant.id, &tip, 1);
    let txs = vec![
        org.sign(Tx::MandateCreate {
            id: m0, parent: None, holder: org.id, asset: usd, rate_per_sec: 0,
            buffer_max: 10 * M, per_tx_max: 10 * M, initial_buffer: 10 * M, expiry: 10_000, tier: 2,
        }),
        org.sign(Tx::ChannelOpen {
            id: ch_id, mandate: m0, payee: merchant.id, asset: usd, tip,
            unit_price: 10_000, max_steps: 100, expiry: 500, // escrow 1M
        }),
        merchant.sign(Tx::ChannelSettle { id: ch_id, word: H256(chain.pay(40).unwrap()), step: 40 }),
    ];
    let r = st.apply_block(1, 110, &txs).unwrap();
    assert!(r.iter().all(|x| x.result.is_ok()), "{r:?}");

    // Refund before expiry fails; after expiry returns the remaining 60 steps' escrow.
    let refund_early = vec![org.sign(Tx::ChannelRefund { id: ch_id })];
    let r_early = st.apply_block(2, 200, &refund_early).unwrap();
    assert!(r_early[0].result.as_ref().unwrap_err().contains("not yet expired"));
    org.rollback();

    let refund_late = vec![org.sign(Tx::ChannelRefund { id: ch_id })];
    let r_late = st.apply_block(3, 600, &refund_late).unwrap();
    assert!(r_late[0].result.is_ok(), "{:?}", r_late[0]);
    assert_eq!(st.balance(&org.id, &usd), 9 * M + 600_000); // 10M − 1M escrow + 0.6M refund
    assert_eq!(st.balance(&merchant.id, &usd), 400_000); // 40 × 10_000

    // Settle after refund is rejected.
    let late_settle = vec![merchant.sign(Tx::ChannelSettle { id: ch_id, word: H256(chain.pay(50).unwrap()), step: 50 })];
    let r_settle = st.apply_block(4, 700, &late_settle).unwrap();
    assert!(r_settle[0].result.as_ref().unwrap_err().contains("refunded"));
}

#[test]
fn attenuation_enforced_at_creation() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"org3");
    let genesis = Genesis { time: 100, accounts: vec![org.genesis()], alloc: vec![(org.id, usd, M)], fee: None };
    let mut st = State::from_genesis(&genesis).unwrap();
    let (m0, bad) = (h(0xC0), h(0xC1));
    let txs = vec![
        org.sign(Tx::MandateCreate {
            id: m0, parent: None, holder: org.id, asset: usd, rate_per_sec: 0,
            buffer_max: M, per_tx_max: M, initial_buffer: M, expiry: 1_000, tier: 2,
        }),
        // Child tries to OUTLIVE the parent — must be rejected (Biscuit-style narrowing).
        org.sign(Tx::MandateCreate {
            id: bad, parent: Some(m0), holder: org.id, asset: usd, rate_per_sec: 0,
            buffer_max: M, per_tx_max: M, initial_buffer: 0, expiry: 2_000, tier: 0,
        }),
    ];
    let r = st.apply_block(1, 110, &txs).unwrap();
    assert!(r[0].result.is_ok());
    assert!(r[1].result.as_ref().unwrap_err().contains("attenuation"), "{:?}", r[1]);
}

// ---- P2.0: the shielded pool ----

use crate::pool::{full_tree_path, ProofVerifier};
use hk_spend_circuit as circuit;
use std::sync::Arc;

/// Test verifier: the "proof" is the JSON of the public statement the WALLET computed.
/// Verifying = the chain's independently derived expectation matches the wallet's — which
/// exercises the entire binding rule (anchor, nullifier, out_commitment, fee, tx_binding).
/// WS2 swaps this for the real SP1 STARK verifier; the state machine is identical.
struct JsonEchoVerifier;

impl ProofVerifier for JsonEchoVerifier {
    fn verify_spend(&self, proof: &[u8], expected: &circuit::SpendPublic) -> bool {
        serde_json::from_slice::<circuit::SpendPublic>(proof).map(|p| p == *expected).unwrap_or(false)
    }
    fn verify_mint(&self, proof: &[u8], expected: &circuit::MintPublic) -> bool {
        serde_json::from_slice::<circuit::MintPublic>(proof).map(|p| p == *expected).unwrap_or(false)
    }
}

/// P2.3: a PROOF-LESS pool tx is accepted iff the block's aggregation coverage contains
/// its (kind, expected-publics) key — installed by the node only after the batch's
/// aggregate STARK verified. Coverage expires with the block.
#[test]
fn aggregated_coverage_accepts_proofless_txs() {
    use crate::pool::cover_key;
    use hk_spend_circuit::agg::KIND_MINT;

    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"org-agg");
    let genesis = Genesis {
        time: 100,
        accounts: vec![org.genesis()],
        alloc: vec![(org.id, usd, 10 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap(); // verifier = RejectAll

    let master: &[u8] = b"agg-note-master";
    let owner = circuit::address_tag(&circuit::spend_root(master, 2), &circuit::derive_nk(master));
    let note = circuit::Note { value: (5 * M) as u64, owner, rho: [0x91; 32], rcm: [0x92; 32] };
    let cm = circuit::commit_note(&note);
    let mint_tx = Tx::MintToPool {
        asset: usd,
        value: 5 * M,
        commitment: H256(cm),
        proof: Vec::new(), // PROOF-LESS — rides the aggregate
        stealth_ct: Vec::new(),
    };

    // Without coverage: refused (RejectAll + empty coverage — the secure default).
    let b1 = vec![org.sign(mint_tx.clone())];
    let r1 = st.apply_block(1, 110, &b1).unwrap();
    assert!(r1[0].result.as_ref().unwrap_err().contains("proof rejected"), "{:?}", r1[0]);
    org.rollback();

    // The node verified the batch aggregate → installs coverage → the SAME tx applies.
    let expected = crate::expected_mint_public(&H256(cm), 5 * M);
    let pb = bincode::serialize(&expected).unwrap();
    st.set_block_coverage([cover_key(KIND_MINT, &pb)].into_iter().collect());
    let b2 = vec![org.sign(mint_tx)];
    let r2 = st.apply_block(2, 120, &b2).unwrap();
    assert!(r2[0].result.is_ok(), "{:?}", r2[0]);
    assert_eq!(st.pool.total_shielded, 5 * M);

    // Coverage expired with block 2: a fresh proof-less mint is refused again.
    let note2 = circuit::Note { value: M as u64, owner, rho: [0x93; 32], rcm: [0x94; 32] };
    let b3 = vec![org.sign(Tx::MintToPool {
        asset: usd,
        value: M,
        commitment: H256(circuit::commit_note(&note2)),
        proof: Vec::new(),
        stealth_ct: Vec::new(),
    })];
    let r3 = st.apply_block(3, 130, &b3).unwrap();
    assert!(r3[0].result.as_ref().unwrap_err().contains("proof rejected"), "{:?}", r3[0]);
    org.rollback();
}

/// P2.4: a mandate-bound unshield clears the whole ancestor chain on the PUBLIC fee —
/// caps enforced in consensus while balances stay hidden. Overspend gets the iconic
/// receipt; the rejected note's nullifier is NOT burned.
#[test]
fn mandated_unshield_respects_the_envelope() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"org-mand");
    let mut agent = Keychain::new(b"agent-mand");
    let merchant = Keychain::new(b"merchant-mand");
    let genesis = Genesis {
        time: 100,
        accounts: vec![org.genesis(), agent.genesis(), merchant.genesis()],
        alloc: vec![(org.id, usd, 50 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();
    st.verifier = Arc::new(JsonEchoVerifier);

    // Mandates: root ENVELOPE $15 (per-tx allowance wide, so attenuation holds), agent
    // leaf capped $20 — oversubscribed on purpose.
    let (m0, ma) = (h(0xD0), h(0xD1));
    let mk = |id, parent, holder, buffer: Amount, per_tx: Amount| Tx::MandateCreate {
        id, parent, holder, asset: usd, rate_per_sec: 0, buffer_max: buffer, per_tx_max: per_tx,
        initial_buffer: buffer, expiry: 1_000_000, tier: 0,
    };
    let b1 = vec![
        org.sign(mk(m0, None, org.id, 15 * M, 50 * M)),
        org.sign(mk(ma, Some(m0), agent.id, 20 * M, 20 * M)),
    ];
    let r1 = st.apply_block(1, 110, &b1).unwrap();
    assert!(r1.iter().all(|r| r.result.is_ok()), "{r1:?}");

    // Agent holds a $20 shielded note (minted directly for the test).
    let master: &[u8] = b"agent-note";
    let nk = circuit::derive_nk(master);
    let owner = circuit::address_tag(&circuit::spend_root(master, 2), &nk);
    let note = circuit::Note { value: (20 * M) as u64, owner, rho: [0xA1; 32], rcm: [0xA2; 32] };
    let cm = circuit::commit_note(&note);
    let mint_pub = circuit::MintPublic { commitment: cm, value: (20 * M) as u64 };
    let b2 = vec![org.sign(Tx::MintToPool {
        asset: usd, value: 20 * M, commitment: H256(cm),
        proof: serde_json::to_vec(&mint_pub).unwrap(), stealth_ct: Vec::new(),
    })];
    assert!(st.apply_block(2, 120, &b2).unwrap()[0].result.is_ok());
    let anchor = *st.pool.latest_anchor().unwrap();

    // Agent tries to unshield $16 under its $20 leaf — but the ROOT envelope is $15.
    let (siblings, _) = full_tree_path(&[cm], 0);
    let fee = 16 * M;
    let binding = circuit::tx_binding_for(&merchant.id.0, fee as u64);
    let (sig, ots_path) = circuit::spend_auth(master, 2, 0, &binding);
    let witness = circuit::SpendWitness {
        in_note: note, path: circuit::MerklePath { siblings, index: 0 }, sig, ots_path, nk,
        out_note: circuit::Note { value: (4 * M) as u64, owner, rho: [0xA3; 32], rcm: [0xA4; 32] },
        out2_note: circuit::Note { value: 0, owner: [0; 32], rho: [0xA5; 32], rcm: [0xA6; 32] },
        fee: fee as u64, tx_binding: binding,
    };
    let spend_public = circuit::run(&witness).unwrap();
    let mk_spend = |fee: Amount, public: &circuit::SpendPublic| Tx::ShieldedSpend {
        anchor: H256(anchor), nullifier: H256(public.nullifier),
        out_commitment: H256(public.out_commitment), out2_commitment: H256(public.out2_commitment),
        fee, credit: Some(merchant.id), mandate: Some(ma),
        proof: serde_json::to_vec(public).unwrap(),
        stealth_ct: Vec::new(), stealth_ct2: Vec::new(),
    };
    // Overspend: leaf allows 16, the ROOT (depth 1) has only 15 → the iconic receipt.
    let b3 = vec![agent.sign(mk_spend(fee, &spend_public))];
    let r3 = st.apply_block(3, 130, &b3).unwrap();
    let err = r3[0].result.as_ref().unwrap_err();
    assert!(err.contains("insufficient buffer at depth 1"), "got: {err}");
    agent.rollback();
    assert!(!st.pool.nullifiers.contains(&spend_public.nullifier), "nothing half-applied");

    // A $10 unshield fits every envelope — but only the HOLDER may use the mandate.
    let fee2 = 10 * M;
    let binding2 = circuit::tx_binding_for(&merchant.id.0, fee2 as u64);
    let (sig2, ots_path2) = circuit::spend_auth(master, 2, 1, &binding2);
    let witness2 = circuit::SpendWitness {
        in_note: circuit::Note { value: (20 * M) as u64, owner, rho: [0xA1; 32], rcm: [0xA2; 32] },
        path: { let (s, _) = full_tree_path(&[cm], 0); circuit::MerklePath { siblings: s, index: 0 } },
        sig: sig2, ots_path: ots_path2, nk,
        out_note: circuit::Note { value: (10 * M) as u64, owner, rho: [0xA7; 32], rcm: [0xA8; 32] },
        out2_note: circuit::Note { value: 0, owner: [0; 32], rho: [0xA9; 32], rcm: [0xAA; 32] },
        fee: fee2 as u64, tx_binding: binding2,
    };
    let public2 = circuit::run(&witness2).unwrap();
    // Wrong holder (org relays a mandate it doesn't hold) → refused.
    let b4 = vec![org.sign(mk_spend(fee2, &public2))];
    let r4 = st.apply_block(4, 140, &b4).unwrap();
    assert!(r4[0].result.as_ref().unwrap_err().contains("holder"), "{:?}", r4[0]);
    org.rollback();
    // The holder succeeds; the merchant is paid; the mandate envelope shrinks.
    let b5 = vec![agent.sign(mk_spend(fee2, &public2))];
    let r5 = st.apply_block(5, 150, &b5).unwrap();
    assert!(r5[0].result.is_ok(), "{:?}", r5[0]);
    assert_eq!(st.balance(&merchant.id, &usd), 10 * M);
    assert_eq!(st.pool.total_shielded, 10 * M);
}

/// The P2.0 storyline: secure default refuses everything → org shields $5 → spends a
/// hidden note (change stays shielded, $1 unshields to the merchant via the fee channel)
/// → double spend / unknown anchor / creditless fee all refused → two nodes replay to the
/// identical commitment, pool and all.
#[test]
fn shielded_pool_storyline() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"org-pool");
    let mut merchant = Keychain::new(b"merchant-pool");
    let genesis = Genesis {
        time: 100,
        accounts: vec![org.genesis(), merchant.genesis()],
        alloc: vec![(org.id, usd, 10 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();

    // WALLET side (v3): the org's shielded ADDRESS — spend-tree root + nullifier key.
    let master: &[u8] = b"org-shield-master";
    let nk = circuit::derive_nk(master);
    let owner = circuit::address_tag(&circuit::spend_root(master, 2), &nk);
    let note = circuit::Note { value: (5 * M) as u64, owner, rho: [0x51; 32], rcm: [0x52; 32] };
    let cm = circuit::commit_note(&note);
    let mint_public = circuit::MintPublic { commitment: cm, value: (5 * M) as u64 };
    let mint_tx = Tx::MintToPool {
        asset: usd,
        value: 5 * M,
        commitment: H256(cm),
        proof: serde_json::to_vec(&mint_public).unwrap(),
        stealth_ct: Vec::new(),
    };

    // Block 1 — SECURE DEFAULT: no verifier wired ⇒ even a well-formed mint is refused.
    let b1 = vec![org.sign(mint_tx.clone())];
    let r1 = st.apply_block(1, 110, &b1).unwrap();
    assert!(r1[0].result.as_ref().unwrap_err().contains("proof rejected"), "{:?}", r1[0]);
    org.rollback();

    // Node config: inject the verifier (WS2 injects the real SP1 one here).
    st.verifier = Arc::new(JsonEchoVerifier);

    // Block 2 — shield $5: balance drops, commitment enters the tree, ledger knows $5.
    let b2 = vec![org.sign(mint_tx.clone())];
    let r2 = st.apply_block(2, 120, &b2).unwrap();
    assert!(r2[0].result.is_ok(), "{:?}", r2[0]);
    assert_eq!(st.balance(&org.id, &usd), 5 * M);
    assert_eq!(st.pool.total_shielded, 5 * M);
    assert_eq!(st.pool.tree.next_index(), 1);
    let anchor = *st.pool.latest_anchor().unwrap();

    // WALLET side (v3): rebuild the path, authorize with spend-tree leaf 0, TWO outputs
    // (pay stays shielded as the change; $1 unshields via the fee) — run natively.
    let (siblings, root) = full_tree_path(&[cm], 0);
    assert_eq!(root, anchor, "wallet view of the tree == chain anchor");
    let fee = M; // the unshielded part, paid transparently to the merchant
    let out_note = circuit::Note {
        value: (4 * M) as u64,
        owner, // change back to our own address
        rho: [0x61; 32],
        rcm: [0x62; 32],
    };
    let out2_note = circuit::Note { value: 0, owner: [0x0F; 32], rho: [0x71; 32], rcm: [0x72; 32] };
    let binding = circuit::tx_binding_for(&merchant.id.0, fee as u64);
    let (sig, ots_path) = circuit::spend_auth(master, 2, 0, &binding);
    let witness = circuit::SpendWitness {
        in_note: note,
        path: circuit::MerklePath { siblings, index: 0 },
        sig,
        ots_path,
        nk,
        out_note,
        out2_note,
        fee: fee as u64,
        tx_binding: binding,
    };
    let spend_public = circuit::run(&witness).expect("wallet witness satisfies the statement");
    assert_eq!(spend_public.merkle_root, anchor);
    let spend_tx = Tx::ShieldedSpend {
        anchor: H256(anchor),
        nullifier: H256(spend_public.nullifier),
        out_commitment: H256(spend_public.out_commitment),
        out2_commitment: H256(spend_public.out2_commitment),
        fee,
        credit: Some(merchant.id),
        mandate: None,
        proof: serde_json::to_vec(&spend_public).unwrap(),
        stealth_ct: Vec::new(),
        stealth_ct2: Vec::new(),
    };

    // Block 3 — the spend: nullifier burned, change admitted, $1 unshielded to merchant.
    let b3 = vec![merchant.sign(spend_tx.clone())]; // merchant RELAYS; the proof authorizes
    let r3 = st.apply_block(3, 130, &b3).unwrap();
    assert!(r3[0].result.is_ok(), "{:?}", r3[0]);
    assert_eq!(st.balance(&merchant.id, &usd), M);
    assert_eq!(st.pool.total_shielded, 4 * M);
    assert!(st.pool.nullifiers.contains(&spend_public.nullifier));
    assert_eq!(st.pool.tree.next_index(), 3, "mint + two spend outputs");

    // Block 4 — double spend: same nullifier again → refused by consensus.
    let b4 = vec![merchant.sign(spend_tx.clone())];
    let r4 = st.apply_block(4, 140, &b4).unwrap();
    assert!(r4[0].result.as_ref().unwrap_err().contains("double spend"), "{:?}", r4[0]);
    merchant.rollback();

    // Block 5 — an anchor the chain never had, and a fee with nobody to pay: both refused.
    let b5 = vec![
        org.sign(Tx::ShieldedSpend {
            anchor: h(0xEE),
            nullifier: h(0xE1),
            out_commitment: h(0xE2),
            out2_commitment: h(0xE5),
            fee: 0,
            credit: None,
            mandate: None,
            proof: serde_json::to_vec(&spend_public).unwrap(),
            stealth_ct: Vec::new(),
            stealth_ct2: Vec::new(),
        }),
        merchant.sign(Tx::ShieldedSpend {
            anchor: H256(*st.pool.latest_anchor().unwrap()),
            nullifier: h(0xE3),
            out_commitment: h(0xE4),
            out2_commitment: h(0xE6),
            fee: M,
            credit: None,
            mandate: None,
            proof: serde_json::to_vec(&spend_public).unwrap(),
            stealth_ct: Vec::new(),
            stealth_ct2: Vec::new(),
        }),
    ];
    let r5 = st.apply_block(5, 150, &b5).unwrap();
    assert!(r5[0].result.as_ref().unwrap_err().contains("unknown pool anchor"), "{:?}", r5[0]);
    assert!(r5[1].result.as_ref().unwrap_err().contains("requires a credit account"), "{:?}", r5[1]);
    org.rollback();
    merchant.rollback();

    // Determinism: a second node with the same verifier SCHEDULE replays every block to
    // the identical commitment — pool root, anchors, nullifiers, ledger and all.
    let mut st2 = State::from_genesis(&genesis).unwrap();
    st2.apply_block(1, 110, &b1).unwrap();
    st2.verifier = Arc::new(JsonEchoVerifier);
    st2.apply_block(2, 120, &b2).unwrap();
    st2.apply_block(3, 130, &b3).unwrap();
    st2.apply_block(4, 140, &b4).unwrap();
    st2.apply_block(5, 150, &b5).unwrap();
    assert_eq!(st.state_commitment(), st2.state_commitment());
}

/// P3.0 / WS-B KEYSTONE: snapshot → bincode → restore reaches the IDENTICAL state
/// commitment, and the restored machine keeps running identically — including the
/// pool frontier (which the commitment does NOT cover: index+root only, so this test
/// is what proves a snapshot carries enough to keep appending correctly).
#[test]
fn snapshot_roundtrip_identical_commitment_and_keeps_running() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut org = Keychain::new(b"snap-org");
    let mut a = Keychain::new(b"snap-agent");
    let mut merchant = Keychain::new(b"snap-merchant");
    let genesis = Genesis {
        time: 1_000,
        accounts: vec![org.genesis(), a.genesis(), merchant.genesis()],
        alloc: vec![(org.id, usd, 50 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();

    // A real storyline so every module has content: mandates + a spend + a channel.
    let (m0, ma) = (h(0xF0), h(0xF1));
    let chain = PaywordChain::mint(b"snap-seed", b"snap-session", 100);
    let tip = H256(chain.tip());
    let txs1 = vec![
        org.sign(Tx::MandateCreate {
            id: m0, parent: None, holder: org.id, asset: usd, rate_per_sec: 0,
            buffer_max: 50 * M, per_tx_max: 50 * M, initial_buffer: 50 * M,
            expiry: 1_000_000, tier: 2,
        }),
        org.sign(Tx::MandateCreate {
            id: ma, parent: Some(m0), holder: a.id, asset: usd, rate_per_sec: 0,
            buffer_max: 20 * M, per_tx_max: 20 * M, initial_buffer: 20 * M,
            expiry: 1_000_000, tier: 0,
        }),
    ];
    assert!(st.apply_block(1, 1_010, &txs1).unwrap().iter().all(|r| r.result.is_ok()));
    let ch_id = State::derive_channel_id(&a.id, &merchant.id, &tip, 0);
    let txs2 = vec![
        a.sign(Tx::ChannelOpen {
            id: ch_id, mandate: ma, payee: merchant.id, asset: usd, tip,
            unit_price: 5_000, max_steps: 100, expiry: 900_000,
        }),
        merchant.sign(Tx::ChannelSettle { id: ch_id, word: H256(chain.pay(40).unwrap()), step: 40 }),
    ];
    assert!(st.apply_block(2, 1_020, &txs2).unwrap().iter().all(|r| r.result.is_ok()));

    // Pool content without proof machinery: the fields are consensus state; poke them
    // the way applied mints/spends would (frontier appends, nullifier, ledger, anchor).
    st.pool.tree.append([0xC1; 32]).unwrap();
    st.pool.tree.append([0xC2; 32]).unwrap();
    st.pool.tree.append([0xC3; 32]).unwrap();
    st.pool.nullifiers.insert([0xD1; 32]);
    st.pool.total_shielded = 777;
    st.pool.seal_anchor();

    // Snapshot → bytes → restore.
    let bytes = bincode::serialize(&st.to_snapshot()).expect("snapshot serializes");
    let snap: crate::StateSnapshot = bincode::deserialize(&bytes).expect("snapshot deserializes");
    let mut st2 = State::from_snapshot(snap);
    assert_eq!(st.state_commitment(), st2.state_commitment(), "restore == original C(Σ)");

    // Frontier + recomputed empty ladder must keep producing the SAME roots.
    st.pool.tree.append([0xC4; 32]).unwrap();
    st2.pool.tree.append([0xC4; 32]).unwrap();
    assert_eq!(st.pool.tree.root(), st2.pool.tree.root(), "restored frontier keeps appending");
    st.pool.seal_anchor();
    st2.pool.seal_anchor();

    // And the whole machine keeps running identically on the next block.
    let txs3 = vec![merchant.sign(Tx::Transfer { to: a.id, asset: usd, amount: 3_000 })];
    st.apply_block(3, 1_030, &txs3).unwrap();
    st2.apply_block(3, 1_030, &txs3).unwrap();
    assert_eq!(st.state_commitment(), st2.state_commitment(), "replays stay in lockstep");
}

/// U1 — THE FAUCET FLOW, AS A TEST: a funded account creates + funds a brand-new
/// runtime account (id derived from its auth commitment), and the newcomer can spend
/// immediately with its own L-ratchet. Squat, duplicate, and overdraft all refuse
/// without moving money.
#[test]
fn u1_runtime_account_creation_faucet_flow() {
    const M: Amount = 1_000_000;
    let usd = h(9);
    let mut faucet = Keychain::new(b"faucet-treasury");
    let genesis = Genesis {
        time: 1_000,
        accounts: vec![faucet.genesis()],
        alloc: vec![(faucet.id, usd, 100 * M)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();
    let bal = |st: &State, id: H256| st.balances.get(&(id, usd)).copied().unwrap_or(0);

    // The newcomer generates keys FIRST; the id derives from the auth commitment.
    let mut alice = Keychain::new(b"alice-fresh-entropy");
    let alice_auth0 = alice.commit_at(0);
    let alice_id = H256(shake256_32(DOM_ACCOUNT_ID, &[&alice_auth0.0]));
    alice.id = alice_id; // envelopes must be sent as the DERIVED id

    // 1) Squat attempt: id ≠ H(auth_commit) → refused, faucet not debited.
    let squat = faucet.sign(Tx::AccountCreate {
        id: h(0xAA),
        auth_commit: alice_auth0,
        asset: usd,
        amount: 5 * M,
    });
    let r = st.apply_block(1, 1_010, &[squat]).unwrap();
    assert!(r[0].result.is_err(), "squatted id must refuse");
    assert_eq!(bal(&st, faucet.id), 100 * M, "failed create must not debit");
    faucet.rollback();

    // 2) The real create + fund.
    let create = faucet.sign(Tx::AccountCreate {
        id: alice_id,
        auth_commit: alice_auth0,
        asset: usd,
        amount: 5 * M,
    });
    let r = st.apply_block(2, 1_020, &[create]).unwrap();
    assert!(r[0].result.is_ok(), "{:?}", r[0].result);
    assert_eq!(bal(&st, alice_id), 5 * M);
    assert_eq!(bal(&st, faucet.id), 95 * M);

    // 3) Duplicate create of the same id → refused, no double-debit.
    let dup = faucet.sign(Tx::AccountCreate {
        id: alice_id,
        auth_commit: alice_auth0,
        asset: usd,
        amount: 5 * M,
    });
    let r = st.apply_block(3, 1_030, &[dup]).unwrap();
    assert!(r[0].result.is_err(), "duplicate id must refuse");
    assert_eq!(bal(&st, faucet.id), 95 * M);
    faucet.rollback();

    // 4) The newcomer spends immediately — her ratchet starts at nonce 0.
    let pay = alice.sign(Tx::Transfer { to: faucet.id, asset: usd, amount: 2 * M });
    let r = st.apply_block(4, 1_040, &[pay]).unwrap();
    assert!(r[0].result.is_ok(), "{:?}", r[0].result);
    assert_eq!(bal(&st, alice_id), 3 * M);
    assert_eq!(bal(&st, faucet.id), 97 * M);

    // 5) Unfunded creation (amount = 0) is legal — account exists, balance zero.
    let mut bob = Keychain::new(b"bob-fresh-entropy");
    let bob_auth0 = bob.commit_at(0);
    let bob_id = H256(shake256_32(DOM_ACCOUNT_ID, &[&bob_auth0.0]));
    bob.id = bob_id;
    let create0 = faucet.sign(Tx::AccountCreate {
        id: bob_id,
        auth_commit: bob_auth0,
        asset: usd,
        amount: 0,
    });
    let r = st.apply_block(5, 1_050, &[create0]).unwrap();
    assert!(r[0].result.is_ok(), "{:?}", r[0].result);
    assert_eq!(bal(&st, bob_id), 0);
}

#[test]
fn u4_flat_protocol_fee_burn_refund_and_activation() {
    const M: Amount = 1_000_000;
    let usd = h(9); // == FEE_ASSET
    let mut org = Keychain::new(b"u4-org");
    let mut bob = Keychain::new(b"u4-bob");
    let genesis = Genesis {
        time: 1_000,
        accounts: vec![org.genesis(), bob.genesis()],
        alloc: vec![(org.id, usd, 10 * M), (bob.id, usd, 150)], fee: None
    };
    let mut st = State::from_genesis(&genesis).unwrap();
    st.fee_micro = 100;
    st.fee_from = 3; // activation boundary: heights 1–2 are free
    let bal = |st: &State, id: H256| st.balances.get(&(id, usd)).copied().unwrap_or(0);
    let pre_fee_commitment_is_v11_shaped = st.fees_burned == 0;
    assert!(pre_fee_commitment_is_v11_shaped);

    // 1) PRE-ACTIVATION: a transfer at height 1 pays no fee.
    let t = org.sign(Tx::Transfer { to: bob.id, asset: usd, amount: 1 * M });
    let r = st.apply_block(1, 1_010, &[t]).unwrap();
    assert!(r[0].result.is_ok());
    assert_eq!(bal(&st, org.id), 9 * M, "no fee before activation");
    assert_eq!(st.fees_burned, 0);

    // 2) Empty block crosses the boundary.
    st.apply_block(2, 1_020, &[]).unwrap();

    // 3) POST-ACTIVATION: fee charged and BURNED on success.
    let t = org.sign(Tx::Transfer { to: bob.id, asset: usd, amount: 1 * M });
    let r = st.apply_block(3, 1_030, &[t]).unwrap();
    assert!(r[0].result.is_ok());
    assert_eq!(bal(&st, org.id), 8 * M - 100, "amount + fee left the sender");
    assert_eq!(st.fees_burned, 100);
    let c_after_burn = st.state_commitment();

    // 4) REFUSAL REFUNDS: an overdraft refuses and the fee comes back.
    let before = bal(&st, org.id);
    let t = org.sign(Tx::Transfer { to: bob.id, asset: usd, amount: 100 * M });
    let r = st.apply_block(4, 1_040, &[t]).unwrap();
    assert!(r[0].result.is_err(), "overdraft must refuse");
    assert_eq!(bal(&st, org.id), before, "refused tx must not cost the fee");
    assert_eq!(st.fees_burned, 100, "no burn on refusal");
    org.rollback();

    // 5) The tx's own spend sees the post-fee balance: a full-balance sweep refuses.
    let sweep = org.sign(Tx::Transfer { to: bob.id, asset: usd, amount: before });
    let r = st.apply_block(5, 1_050, &[sweep]).unwrap();
    assert!(r[0].result.is_err(), "full-balance sweep can no longer pay amount+fee");
    assert_eq!(bal(&st, org.id), before);
    org.rollback();

    // 6) Too poor for the fee itself → InsufficientFee (bob holds 150 + 2M received).
    //    Drain bob down first so only 50 micro remain.
    let drain = bob.sign(Tx::Transfer { to: org.id, asset: usd, amount: 2 * M });
    let r = st.apply_block(6, 1_060, &[drain]).unwrap();
    assert!(r[0].result.is_ok());
    assert_eq!(bal(&st, bob.id), 150 - 100, "bob paid the fee on his drain tx");
    let broke = bob.sign(Tx::Transfer { to: org.id, asset: usd, amount: 1 });
    let r = st.apply_block(7, 1_070, &[broke]).unwrap();
    let msg = r[0].result.clone().unwrap_err();
    assert!(msg.contains("protocol fee"), "expected the fee refusal, got: {msg}");
    bob.rollback();

    // 7) Snapshot v2 roundtrip preserves the burn counter AND the commitment.
    let snap = st.to_snapshot();
    let mut back = State::from_snapshot(snap);
    assert_eq!(back.fees_burned, st.fees_burned);
    assert_eq!(back.state_commitment(), st.state_commitment());
    // Fee CONFIG is deliberately not snapshotted — the node re-injects it.
    assert_eq!(back.fee_from, u64::MAX);
    let _ = c_after_burn;
}

#[test]
fn u4b_genesis_bound_fee_policy_applies_from_block_one() {
    const M: Amount = 1_000_000;
    let usd = h(9); // == FEE_ASSET
    let mut org = Keychain::new(b"u4b-org");
    let bob = Keychain::new(b"u4b-bob");
    let genesis = Genesis {
        time: 1_000,
        accounts: vec![org.genesis(), bob.genesis()],
        alloc: vec![(org.id, usd, 10 * M)],
        fee: Some(GenesisFee { micro: 100, from_height: 1 }),
    };
    let st0 = State::from_genesis(&genesis).unwrap();
    assert_eq!((st0.fee_micro, st0.fee_from), (100, 1), "genesis pins the policy");
    // The pinned policy is NOT part of C(Σ) at genesis (fees_burned is still 0), so a
    // genesis with a fee field and one without agree on the empty chain's commitment —
    // policy lives in the genesis DIGEST (the chain id), the state hashes outcomes.
    let plain = State::from_genesis(&Genesis { fee: None, ..genesis.clone() }).unwrap();
    assert_eq!(st0.state_commitment(), plain.state_commitment());

    let mut st = st0;
    let bal = |st: &State, id: H256| st.balances.get(&(id, usd)).copied().unwrap_or(0);
    let t = org.sign(Tx::Transfer { to: bob.id, asset: usd, amount: 1 * M });
    let r = st.apply_block(1, 1_010, &[t]).unwrap();
    assert!(r[0].result.is_ok(), "{:?}", r[0].result);
    assert_eq!(bal(&st, org.id), 9 * M - 100, "fee charged on the very first block");
    assert_eq!(st.fees_burned, 100);

    // JSON round-trip keeps the field; a genesis without it deserializes to None.
    let js = serde_json::to_string(&genesis).unwrap();
    assert!(js.contains("\"fee\""));
    let back: Genesis = serde_json::from_str(&js).unwrap();
    assert_eq!(back.fee, genesis.fee);
    let legacy: Genesis = serde_json::from_str(r#"{"time":1,"accounts":[],"alloc":[]}"#).unwrap();
    assert!(legacy.fee.is_none(), "pre-v0.13 genesis files still parse");
    assert!(!serde_json::to_string(&legacy).unwrap().contains("fee"), "None is not serialized");
}
