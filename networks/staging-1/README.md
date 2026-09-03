# HashKinetics staging network — RETIRED 2026-09-02 (archived)

> **staging-1 (`hashkinetics-1-557f2ea6`) ran 2026-08-27 → 2026-09-02 and stopped at
> height 107,182** (validators 107,176–107,182 at the stop). It was replaced by
> **testnet-1** — fresh genesis, protocol fee from block 1, faucet treasury at genesis —
> see [`../testnet-1/`](../testnet-1/README.md). This kit stays as the record: the genesis
> below is still the one every archived block chains back to, and the full block log
> (snapshot + 107k blocks) is retained by the operators so THE RECEIPT (independent
> byte-for-byte re-verification, 2026-08-31) remains reproducible on request.
> The join instructions below no longer connect to a live network.

> **⚠ Minimum node version: v0.12.2 from height 110,000** (never reached — the network was archived at 107,182). The flat protocol fee
> activates at height 110,000 — nodes below v0.12.2 compute different balances from
> that height and will refuse on app_hash divergence. Also inherited: the account-
> creation wire addition (v0.11.0) means pre-v0.11 nodes cannot decode recent history.
> Build from a tag ≥ v0.12.2.

The public staging testnet (the chain behind [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer)
and `https://rpc.hashkinetics.org`). Four founder-operated validators ran it; anyone
can run a **full node** that syncs it, verifies every block, and serves its own RPC
and explorer. Validator seats were ceremony-fixed (see `docs/VALIDATOR-ONBOARDING.md`
for how seats are added on the live network).

**Identity, not topology, defines the network.** The `genesis.json` here — chain id,
validator roots, vk pins — IS the network. A node on this genesis with these peers is
on the real chain; a node that generates its own genesis is simply running a private
devnet (also fine — that's what the demos use). Nothing can fork this chain without
⅔ of its validator keys, so an "accidental island" is impossible: you're either
verifying our history from block 1 or you're on your own chain by construction.

## Join (one screen)

```bash
git clone https://github.com/hashkinetics/hashkinetics
cd hashkinetics/chain && cargo build --release

# your node identity (never leaves your machine):
./target/release/hk-node keygen ~/hk-staging my-observer

# the network artifacts (this directory):
cp ../networks/staging-1/genesis.json ~/hk-staging/genesis.json

# config with the published bootstrap peers:
./target/release/hk-node config-gen ~/hk-staging \
  --listen /ip4/0.0.0.0/tcp/27000 \
  --peers $(paste -sd, ../networks/staging-1/PEERS.txt)

HK_PROVER_URL=https://prover.hashkinetics.org ./target/release/hk-node start ~/hk-staging
```

**`HK_PROVER_URL` is required to sync.** It wires the in-node SP1 STARK verifier
(verifying keys are fetched once and checked against the genesis `vk_pins`).
Without it your node keeps the refuse-all posture and will REJECT the first
canonical block that carries a shielded proof — an `app_hash divergence` wedge
at that height (we did this to ourselves once; see CHANGELOG 0.10.9). Shipping
the verifying keys inside this kit, removing the live dependency, is queued.

Startup must print `SP1 pool verifier wired` and `verifying keys MATCH the genesis pins`, then sync heights.
Your RPC is at `:26000` — point `explorer/index.html` at it and you have your own
window into the chain, served from your own verification.

## Verify you're on the real network

The genesis fingerprint (SHA-256 of `genesis.json` in this directory):

```
557f2ea6c55713ae1a820043baf3900707101e6fceaccc34b05e44f1a5f62a22
```

Check it (`sha256sum genesis.json`) before starting your node. Then, running:

```bash
curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_chainInfo","params":{}}'
```

The `chain_id` and `app_hash` at any height must match the archived block log's
(`https://rpc.hashkinetics.org` now serves testnet-1) — same input, same hash, no trust
required; the final commitment at 107,182 is in CHANGELOG [0.13.0].

## Notes

- Observers hold a validator keypair (from `keygen`) but are not in the validator
  set: you sync and verify, you don't vote. No stake, no cost, no GPU.
- Bootstrap peers are DNS-based (`PEERS.txt`) — IPs may change; the names won't.
- The chain id is bound to genesis: a node reports `hashkinetics-1-<first 8 hex of
  the genesis digest>` — for this network, `hashkinetics-1-557f2ea6`. A node on a
  different genesis reports a different id and is visibly not this chain. `hk_chainInfo`
  also returns the full `genesis_digest` (the fingerprint above).
- Identity, not topology: nodes **refuse to peer across genesis**. A node whose genesis
  digest differs from ours is dropped at connect time, so an "island" chain cannot attach
  to the network — you are either syncing OUR genesis from block 1 or on your own chain.
- Syncing crosses validator-key-rotation boundaries (v0.10.7): certificates are
  verified against the set as of their height, so a fresh node can walk the whole
  chain from block 1 — including every epoch the validators have rotated through.
- Sync throughput: solved (as measured on staging-1). v0.10.8 parallelized catch-up verification (R5.2) —
  measured **71 blocks/min** on deep backlogs on the live testnet (up from ~2),
  faster than the chain advances — and since v0.10.9 syncing spends **zero**
  signer leaves.
