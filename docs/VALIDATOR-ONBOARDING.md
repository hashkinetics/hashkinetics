# HashKinetics — Validator Onboarding (public testnet)

**v0.15.2 · testnet-1.** Run **v0.15.2** (the current release — the kit ships the verifying keys, so your node never depends on our prover; since v0.15.2 your node advertises its version to its peers and appears on the public roll call, `hk_getPeers` / [hashkinetics.org/network#live](https://www.hashkinetics.org/network#live), the moment it connects). Minimum to *sync* **testnet-1** (`hashkinetics-1-4e4ea68d`) is v0.13.0 — the fee policy lives in its genesis, so older nodes cannot decode it — but the network activates appended transaction kinds by height: the first validator-set change (v0.14.0) and the first issued-asset transaction (v0.15.0) each make their release the minimum for every node from that block on (an older node halts there, loudly, by design). A node that wants a seat must be ≥ v0.15.0 before it is admitted. (staging-1 is retired and archived: `networks/staging-1/`.) How an external operator joins a HashKinetics network: generate a key,
send one public JSON blob, receive genesis, start. Every consensus signature you will ever
produce is hash-based (LMS/HSS over SHAKE-256 under a stateless SLH-DSA-192s root) — you are
operating post-quantum BFT.

## 0 · What you need

- Linux (bare or WSL2), 4+ cores, **8 GB RAM minimum** (the node's steady RSS is ~6.7 GB —
  the proof-system verifier's fixed footprint — until R11 lands; 16 GB is comfortable),
  20 GB+ disk (the node is durable: per-height block log + snapshots — plan for growth).
- **No GPU.** Validators VERIFY STARKs in-node on CPU; GPUs are for people *making*
  payments, not validating them.
- Rust (stable) + the public repo: `git clone https://github.com/hashkinetics/hashkinetics`.
- One open inbound TCP port for consensus (default **27000**). Do NOT expose the node RPC
  (26000) publicly — it has no auth; keep it loopback or behind your own proxy.

Build once:
```bash
cd chain && cargo build --release -p hk-node
```

## 1 · Generate your key (stays on your machine, forever)

```bash
hk-node keygen ~/hk-validator my-moniker
```
Writes two files: `priv_validator_key.json` — **SECRET**, back it up offline; it derives both
your consensus key and your permanent SLH-DSA root identity — and `validator.json` — PUBLIC.

## 2 · Send the coordinator two things

Mail **validators@hashkinetics.org** with:

1. The contents of `~/hk-validator/validator.json`.
2. Your public consensus multiaddr: `/ip4/<YOUR-PUBLIC-IP>/tcp/27000`.

That address is also the operator channel for incidents once you're running.

## 3 · Receive and VERIFY genesis

The coordinator assembles every validator.json into `genesis.json` and publishes its
SHA-256 hash out-of-band. Verify before using — a byte different and app hashes fork at
height 1:
```bash
sha256sum genesis.json      # compare to the published digest
cp genesis.json ~/hk-validator/
```
The genesis carries **vk pins**: hashes of the exact proof system this chain accepts. Your
node fetches the verifying-key bytes from the coordinator's prover URL at startup and
**refuses to start unless they match the pins** — so fetching from someone else's server is
trustless.

## 4 · Write your config

```bash
hk-node config-gen ~/hk-validator \
  --listen /ip4/0.0.0.0/tcp/27000 \
  --peers <multiaddrs from networks/testnet-1/PEERS.txt, comma-separated> \
  --moniker my-moniker \
  --gossip-peers http://PEER1.IP:26000,http://PEER2.IP:26000   # optional, see below
```
Peers = the multiaddrs the coordinator circulates (include at least the seed node; more is
better). Firewall: allow inbound 27000/tcp.

**Tx gossip (C2, optional but recommended):** `--gossip-peers` takes the RPC endpoints the
coordinator circulates; your node then pushes every admitted tx to them (single hop), so a
tx submitted anywhere reaches every proposer. To RECEIVE gossip, your own RPC must be
reachable by the other validators — bind it to a peer-facing interface and **firewall it to
the validator IPs only** (the RPC has no auth; the "never expose publicly" rule stands).
Skipping gossip is safe: your node still validates everything; only tx relay is affected.

## 5 · Start (and keep started)

```bash
cp networks/testnet-1/vks.json ~/hk-validator/vks.json   # since v0.15.1: the verifying keys ship in the kit — no prover needed
hk-node start ~/hk-validator
# (pre-v0.15.1 alternative, still supported: HK_PROVER_URL=https://prover.hashkinetics.org — fetches the same pinned keys at startup)
```
As a service, `/etc/systemd/system/hk-node.service`:
```ini
[Unit]
Description=HashKinetics validator
After=network-online.target
[Service]
User=hk
Environment=RUST_LOG=info
# the verifying keys live at /home/hk/hk-validator/vks.json (copied from the kit); set
# Environment=HK_VKS_FILE=<path> to point elsewhere, or HK_PROVER_URL=<prover-url> to fetch them instead
ExecStart=/home/hk/chain/target/release/hk-node start /home/hk/hk-validator
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
`Restart=always` is safe: the node is **durable** — any restart (including `kill -9`)
resumes from its block log + snapshot to a byte-identical state commitment. There is no
"resync from genesis" and no state to lose. Reserve-then-sign signer persistence means a
crash can never reuse a one-time signature leaf.

## 6 · Verify you're live

Startup log must show, in order: `verifying keys MATCH the genesis pins` →
`SP1 pool verifier wired` → `Consensus is ready` → `Committed block` lines whose `app_hash`
matches other validators'. On restarts you'll also see
`PERSISTENCE RESTORE COMPLETE — resuming, not resyncing`. The network explorer (coordinator
— https://www.hashkinetics.org/explorer/ — lists your address under Validators (observers show without a vote).

## 7 · Operating rules

- **Never** run two nodes from the same key material (equivocation; slashable at mainnet).
- **Never** delete `consensus_state*.bin` while keeping the key (one-time-leaf safety).
- **Never** copy `consensus_state*.bin` between machines — it is your signer's
  spent-leaf counter, not chain data. Restoring a node from another node's backup?
  Take `blocks/` + `snapshot.bin` ONLY; your own signer files stay yours.
- **Know your leaf budget.** Your operational tree holds ~32.7K one-time signatures
  ≈ ~10.9K heights at ~3 sigs/height (~6 h at 2 s blocks). Staging incident #1
  (2026-08-28) ran a tree to exactly zero: the chain HALTED rather than reuse a
  leaf — correct behavior, avoidable outage. **Since v0.10.5 rotation is automatic:**
  when your remaining budget crosses <20% (6,553 leaves), your node issues a
  root-signed rotation cert by itself and it rides your next proposal — no env
  vars, no operator action (the fleet has rotated through dozens of epochs
  unattended). Watch it live: `hk_chainInfo.signer {epoch, remaining, capacity}`.
  If you DO exhaust while parked/offline, any peer can carry your revival:
  `hk-node issue-rotation <HOME> <EPOCH>` + `hk_submitRotation` on a live node
  (three production revivals to date).
- **Syncing across rotation history works (v0.10.7):** commit certificates are
  verified against the validator set as of their height, so a new or restarted
  node syncs from genesis (or any snapshot) across every epoch boundary. Since
  v0.13.0 (R10 v2) a restart resumes at the CHAIN height from its snapshot + the
  few blocks after it — no rehydration of history, voting within seconds; older
  history is served to peers from your block log (only the gap-free suffix that
  reaches your tip is advertised). A validator in a hurry can still restore from
  a peer's snapshot near tip (`blocks/` + `snapshot.bin` — snapshot.bin FIRST in
  the tar; never the peer's `consensus_state*.bin`).
- Your key exhausting or your node dying is a **liveness** fault only — the chain continues;
  key rotation under your SLH-DSA root brings you back (SCMS; cert flow is live —
  a rotated validator shows its new epoch badge on the explorer).
- Incidents: RUNBOOK-DEVNET.md §4/§7 troubleshooting tables, then the operator channel.

## Appendix — coordinator's ceremony (reference)

```bash
# Merge the collected blobs into one JSON array (jq if you have it, python otherwise):
jq -s '.' collected/*.validator.json > validators.json
#   — or —
python3 -c "import json,glob; print(json.dumps([json.load(open(f)) for f in sorted(glob.glob('collected/*.validator.json'))], indent=1))" > validators.json

export HK_PROVER_URL=http://<prover-host>:9911             # ALWAYS pin a public testnet
export HK_CHAIN_START_TIME=$(date +%s)
# v0.13.0 (U4.b): the fee policy and the allocations are GENESIS facts —
#   --fee-micro 100 --fee-from 1          flat envelope fee (burned) from the first block; 0 = none
#   --alloc <AUTH0-hex>:<micro>           fund a self-custodied account (id derived from its nonce-0
#                                         auth commitment; `hk-node account-info` prints it as "genesis auth")
#   --demo-accounts [ORG-USD]             the five PUBLIC-seed demo accounts (demo money only)
hk-node genesis-build validators.json genesis.json \
  --fee-micro 100 --fee-from 1 --alloc <TREASURY-AUTH0>:1000000000000 --demo-accounts 50
sha256sum genesis.json                                      # publish this digest + the file
```
The full procedure, the rules behind each step, and the testnet-1 record live in
`docs/CEREMONY-TESTNET-1.md`; `chain/rehearsal.sh` runs the whole ceremony locally first.
Coordinator also runs: the seed node (stable public multiaddr), the hosted prover (vk
endpoint + proving for demo traffic), and the public explorer. **G3 soak clock**: starts
when ≥4 external validators hold ≥⅓ of voting power; 30 days incident-free.

## 8 · From observer to seat (v0.14.0; run v0.15.0)

A seat is admitted on the running chain by a `SetChangeCert` approved by more than ⅔ of the current seats' root keys; it takes effect one height after it commits and your node starts voting with no restart. Preconditions: your observer runs the current release (≥ v0.15.0 — the admission certificate rides a v2-framed block, and issued-asset transactions follow), is at the tip with the canonical `app_hash`, ran with `HK_PROVER_URL` from the first block (a node on this genesis refuses to start without the verifier since v0.14.0), and you sent `validator.json` (public halves only) to validators@hashkinetics.org. Procedure and receipts: `docs/V1-VALIDATOR-SET-CHANGES.md`.
