# HashKinetics testnet-1 — join as a full node

> **Current release: v0.18.1 — every node must run it before height 110,000 (the G1 activation; a node still on ≤ v0.17 — or on the withdrawn v0.18.0, which named 200,000 — stops following there).** (Since v0.17.0 the node verifies with a verify-only STARK client — a restart costs seconds and the resident set is tens of MiB; since v0.15.1 the kit carries the verifying keys, `vks.json`, and the node's client speaks https; since v0.15.2 your node advertises its version to its peers and shows up on [hashkinetics.org/network#live](https://www.hashkinetics.org/network#live) the moment it connects to the gateway). Minimum to sync: v0.13.0 — testnet-1 launched 2026-09-02 from a fresh
> genesis with the protocol fee (100 micro per envelope, burned) **bound in the genesis
> from height 1** and the faucet treasury allocated at genesis — no activation heights,
> no coordinated rolls for the fee. Appended transaction kinds activate by height instead:
> the first validator-set change makes v0.14.0 the minimum, the first issued-asset
> transaction makes v0.15.0 the minimum — an older node halts at that block by design. (Its predecessor, `staging-1`, ran
> 2026-08-27 → 2026-09-02, stopped at height 107,182 and is archived — see `../staging-1/`.)

The public testnet (the chain behind [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer)
and `https://rpc.hashkinetics.org`). Four founder-operated validators run it; anyone
can run a **full node** that syncs it, verifies every block, and serves its own RPC
and explorer. External operators start as **observers**; since v0.14.0 a voting seat
is admitted on the RUNNING chain by a certificate approved by more than ⅔ of the
current seats' root keys — no new genesis (`docs/V1-VALIDATOR-SET-CHANGES.md`)
(`docs/VALIDATOR-ONBOARDING.md`). From height 110,000 (v0.18.1, bootstrap governance)
the four genesis seats weigh 4 each by a published rule, so the founding seats hold more
than ⅔ on their own while the network is this young; the weight returns to external
seats by certificate on a dated milestone (`docs/V1-VALIDATOR-SET-CHANGES.md` §6).
**Every node must run ≥ v0.18.1 before height 110,000.** Since v0.15.0 the chain carries **issued assets**:
an issuer registers an asset, mints, burns, freezes and pauses under a policy fixed at
registration, with supply in the state commitment (`docs/X1-ISSUED-ASSETS.md`;
`hk-node asset …`, `hk_getAssets`). Just want to use it? `https://www.hashkinetics.org/faucet`
and the Windows wallet (`docs/WALLET-GUIDE.md`); every transaction pays 100 micro.

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
./target/release/hk-node keygen ~/hk-testnet-1 my-observer

# the network artifacts (this directory): the pinned genesis AND the verifying keys
cp ../networks/testnet-1/genesis.json ~/hk-testnet-1/genesis.json
cp ../networks/testnet-1/vks.json     ~/hk-testnet-1/vks.json      # since v0.15.1: verify without our prover

# config with the published bootstrap peers:
./target/release/hk-node config-gen ~/hk-testnet-1 \
  --listen /ip4/0.0.0.0/tcp/27000 \
  --peers $(paste -sd, ../networks/testnet-1/PEERS.txt)

./target/release/hk-node start ~/hk-testnet-1
```

**The verifier must be wired to sync**, and since v0.15.1 the kit carries what it needs:
`vks.json` holds the three SP1 verifying keys (104 bytes each); the node reads
`<HOME>/vks.json` (or `HK_VKS_FILE=<path>`), checks every key against the genesis
`vk_pins`, and verifies every STARK locally — **no prover connection, ever**. A
tampered or foreign `vks.json` is refused at startup (`PIN MISMATCH`). The old way,
`HK_PROVER_URL=https://prover.hashkinetics.org` (fetch the same keys from our prover at
startup), still works — and since v0.15.1 the node's own HTTP client speaks https, which
it did not before: on v0.13–v0.15.0 that instruction was impossible on the stock binary
(found by the first external operator, 2026-09-05; `docs/INCIDENTS.md` #10). Without a
verifier a node on this genesis refuses to start (K5) rather than wedge at the first
shielded block.

Startup must print `SP1 pool verifier wired from the vks file` and `verifying keys MATCH the genesis pins`, then sync heights.
Regenerate the file yourself if you distrust ours: `hk-node vks-fetch https://prover.hashkinetics.org -o vks.json --genesis genesis.json` writes it only if the keys match the pins.
Your RPC is at `:26000` — point `explorer/index.html` at it and you have your own
window into the chain, served from your own verification.

## Verify you're on the real network

The genesis fingerprint (SHA-256 of `genesis.json` in this directory):

```
4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7
```

Check it (`sha256sum genesis.json`) before starting your node. Then, running:

```bash
curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_chainInfo","params":{}}'
```

The `chain_id` and `app_hash` at any height must match what
`https://rpc.hashkinetics.org` reports — same input, same hash, no trust required.

## Notes

- Observers hold a validator keypair (from `keygen`) but are not in the validator
  set: you sync and verify, you don't vote. No stake, no cost, no GPU. Keep that
  key: it is exactly what a seat admission (v0.14.0) registers, and the seated node
  starts voting from the next height with no restart.
- Bootstrap peers are DNS-based (`PEERS.txt`) — IPs may change; the names won't.
- The chain id is bound to genesis: a node reports `hashkinetics-1-<first 8 hex of
  the genesis digest>` — for this network, `hashkinetics-1-4e4ea68d`. A node on a
  different genesis reports a different id and is visibly not this chain. `hk_chainInfo`
  also returns the full `genesis_digest` (the fingerprint above).
- Identity, not topology: nodes **refuse to peer across genesis**. A node whose genesis
  digest differs from ours is dropped at connect time, so an "island" chain cannot attach
  to the network — you are either syncing OUR genesis from block 1 or on your own chain.
- Syncing crosses validator-key-rotation boundaries (v0.10.7): certificates are
  verified against the set as of their height, so a fresh node can walk the whole
  chain from block 1 — including every epoch the validators have rotated through.
- Fees: every transaction envelope pays **100 micro** of the test asset (burned). Keep a
  little balance back — a full-balance sweep refuses honestly. `hk_chainInfo.fee` shows
  the policy and the running burn counter.
- Memory (v0.13.0, R10 v2): a node keeps only the newest 512 decided heights in RAM
  (`HK_DECIDED_WINDOW`) and serves older history to syncing peers straight from its
  block log; a restart resumes at the chain's height whatever the block log looks like.
  `hk_chainInfo.history` shows what a node can serve from disk.
- Sync throughput: solved. v0.10.8 parallelized catch-up verification (R5.2) —
  measured **71 blocks/min** on deep backlogs on staging-1 (up from ~2),
  faster than the chain advances — and since v0.10.9 syncing spends **zero**
  signer leaves.
