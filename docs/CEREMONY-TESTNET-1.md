# testnet-1 genesis ceremony — procedure and record

> Status: **rehearsed on devnet (chain/rehearsal.sh) → executed on the fleet 2026-09-02 — testnet-1 is live.**
> One deviation from the script: the VM service accounts have read-only object-storage scope, so the genesis was distributed host-to-host over ssh (base64) instead of via a relay bucket, and the staging-1 archive tar could not be pushed by the VM's own identity — it went to object storage from the gateway with a one-hour operator token passed over ssh stdin (never on disk, never in an argument), 2,932,293,982 bytes, 2026-09-02 18:21 UTC. Lesson for the next ceremony: widen the scope (needs a VM stop) or plan the token route from the start.

## What a ceremony is, here

A HashKinetics network is its genesis bytes. `genesis.json` carries the validator set
(SLH-DSA roots + genesis LMS/HSS operational keys), the pinned proof-system verifying
keys, the chain-state allocations, and — from v0.13.0 (U4.b) — the **fee policy**. Its
SHA-256 is the chain id (`hashkinetics-1-<first 8 hex>`); nodes refuse to peer across
digests. So "launching a network" is: independent key generation on every validator host,
one coordinator assembling a genesis from the PUBLIC halves, byte-identical distribution,
and a simultaneous start. Nothing else is shared.

## Rules (each one bought with an incident)

1. **Fresh keys for a fresh chain.** Consensus keys are stateful hash-based signatures
   (LMS/HSS). A tree that has signed on one chain must never sign on another from a
   reset counter — reuse of a one-time leaf is a forgery hazard. `keygen` into a NEW
   home dir; the old home stays untouched for the archive.
2. **Private material never moves.** `priv_validator_key.json` and `consensus_state*.bin`
   stay on their host. Only `validator.json` (public) travels to the coordinator. The
   faucet treasury's seed stays on the gateway; only its nonce-0 auth commitment enters
   the genesis (`hk-node account-info` prints it as "genesis auth").
3. **Fee policy is a genesis fact** (`genesis-build --fee-micro 100 --fee-from 1`). No
   activation roll, no operator environment to agree on; a node started with
   `HK_FEE_*` set on such a network logs that the override is ignored.
4. **Allocations are squat-proof.** `--alloc AUTH0:MICRO` derives the account id from
   the auth commitment exactly like `Tx::AccountCreate` does. Demo accounts
   (`--demo-accounts`) have PUBLIC seeds by design — demo money only.
5. **Byte-identical genesis on every host, checked by digest** before anyone starts.
   `genesis-build` prints the digest and the chain id it implies.
6. **Pinned verifying keys** (`HK_PROVER_URL` at build time) — an unpinned genesis is a
   devnet, never a public network.
7. **Versioned binary + sha on every host** before the start; the live path
   (`/home/yadu/hk-node`) is a copy, never a symlink into a build tree.
8. **Archive the predecessor before the stop**: snapshot FIRST, then the block log
   (a tar that walks blocks before the snapshot can leave the snapshot ahead of the
   tail). One full log is enough for the record; every host keeps its final snapshot.

## Procedure (as scripted in `ops/ceremony-testnet-1.sh`, private)

```
binary   relay the versioned binary to every host; verify sha ×4
keys     hk-node keygen <NEW-HOME> <moniker> on every host (refuses to overwrite); copy config.toml
genesis  collect validator.json ×4 → validators.json → on the coordinator:
           HK_PROVER_URL=… HK_CHAIN_START_TIME=$(date +%s) hk-node genesis-build validators.json genesis.json \
             --fee-micro 100 --fee-from 1 --alloc <TREASURY-AUTH0>:<MICRO> --demo-accounts 50
         distribute → sha256sum genesis.json ×4 must match
archive  predecessor network: snapshot + full block log → object storage
go       stop all four → rename homes (old → *-final, new → live) → live binary ← versioned → start all four → faucet
verify   chain id · height advancing · fee {100, from 1} · treasury balance · validators ×4 · RSS · faucet /health
```

## Rehearsal (chain/rehearsal.sh)

The same procedure on one machine — 4 keygens, genesis-build with fee + treasury + demo
accounts, 4 validators from it — followed by the R10 v2 restore-shape drills and an
observer syncing from genesis against validators whose RAM window is 8 heights (so the
disk path serves everything else). Receipt: see CHANGELOG [0.13.0].

## Record — testnet-1

| field | value |
|---|---|
| launched | 2026-09-02 ~15:25 UTC (21:00 IST) — first blocks within minutes of the start |
| chain id | `hashkinetics-1-4e4ea68d` |
| genesis digest | `4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7` (`chain_start_time` 1788362219) |
| validators | 4 founder-operated seats, fresh keys — consensus addresses `F874765D…`, `42C00CD6…`, `E77F5F47…`, `F7D75524…` (external seats join at the next genesis — see `VALIDATOR-ONBOARDING.md`) |
| fee policy | 100 micro per envelope from height 1, burned |
| treasury | `6c0466c5a22e8c003550165a8aadd8a868aca4657e4c7e9fb48ab14d4df264ad` — 1,000,000,000,000 micro at genesis (seed stays on the gateway) |
| demo accounts | org / agent-a / agent-b / agent-c / merchant (public seeds; org $50) |
| predecessor | staging-1 (`hashkinetics-1-557f2ea6`), 2026-08-27 → 2026-09-02, stopped at height 107,182; full homes retained on every host; the gateway's complete log + final snapshot archived to object storage (`staging-1-gateway.tgz`, 2,932,293,982 bytes) — a copy of the tar also stays on the gateway |
| node version | v0.13.0 minimum |
