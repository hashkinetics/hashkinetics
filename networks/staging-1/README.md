# HashKinetics staging network — join as a full node

The public staging testnet (the chain behind [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer)
and `https://rpc.hashkinetics.org`). Four founder-operated validators run it; anyone
can run a **full node** that syncs it, verifies every block, and serves its own RPC
and explorer. Validator seats are ceremony-fixed until testnet-1 (see
`docs/VALIDATOR-ONBOARDING.md` to join the next genesis).

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

./target/release/hk-node start ~/hk-staging
```

Startup must print `verifying keys MATCH the genesis pins` and then sync heights.
Your RPC is at `:26000` — point `explorer/index.html` at it and you have your own
window into the chain, served from your own verification.

## Verify you're on the real network

The genesis fingerprint (SHA-256 of `genesis.json` in this directory):

```
557f2ea6e55713ae1a820043baf3900707101a6fceaccc34b05a44f1a5f62a22
```

Check it (`sha256sum genesis.json`) before starting your node. Then, running:

```bash
curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_chainInfo","params":{}}'
```

The `chain_id` and `app_hash` at any height must match what
`https://rpc.hashkinetics.org` reports — same input, same hash, no trust required.

## Notes

- Observers hold a validator keypair (from `keygen`) but are not in the validator
  set: you sync and verify, you don't vote. No stake, no cost, no GPU.
- Bootstrap peers are DNS-based (`PEERS.txt`) — IPs may change; the names won't.
- The staging chain id currently reads `hashkinetics-devnet-1` (a ceremony-era
  label); testnet-1's re-genesis sets the proper id. The genesis digest below is
  what actually pins the network.
- Sync throughput is a known work item (R5): expect ~45 blocks/min today on deep
  backlogs.
