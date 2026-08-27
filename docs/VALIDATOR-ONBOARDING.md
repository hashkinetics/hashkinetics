# HashKinetics — Validator Onboarding (public testnet)

**v0.10.x · P3.0c.** How an external operator joins a HashKinetics network: generate a key,
send one public JSON blob, receive genesis, start. Every consensus signature you will ever
produce is hash-based (LMS/HSS over SHAKE-256 under a stateless SLH-DSA-192s root) — you are
operating post-quantum BFT.

## 0 · What you need

- Linux (bare or WSL2), 4+ cores, 8 GB RAM, 20 GB+ disk (the node is durable: per-height
  block log + snapshots — plan for growth).
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

1. The contents of `~/hk-validator/validator.json`.
2. Your public consensus multiaddr: `/ip4/<YOUR-PUBLIC-IP>/tcp/27000`.

## 3 · Receive and VERIFY genesis

The coordinator assembles every validator.json into `genesis.json` and publishes its
SHAKE-256 hash out-of-band. Verify before using — a byte different and app hashes fork at
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
  --peers /ip4/COORD.IP/tcp/27000,/ip4/PEER2.IP/tcp/27000 \
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
export HK_PROVER_URL=<coordinator's prover URL>     # vk fetch, pin-verified
hk-node start ~/hk-validator
```
As a service, `/etc/systemd/system/hk-node.service`:
```ini
[Unit]
Description=HashKinetics validator
After=network-online.target
[Service]
User=hk
Environment=HK_PROVER_URL=<prover-url>
Environment=RUST_LOG=info
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
publishes the URL) should list your address under Validators.

## 7 · Operating rules

- **Never** run two nodes from the same key material (equivocation; slashable at mainnet).
- **Never** delete `consensus_state*.bin` while keeping the key (one-time-leaf safety).
- Your key exhausting or your node dying is a **liveness** fault only — the chain continues;
  key rotation under your SLH-DSA root brings you back (SCMS; cert flow is live).
- Incidents: RUNBOOK-DEVNET.md §4/§7 troubleshooting tables, then the operator channel.

## Appendix — coordinator's ceremony (reference)

```bash
# Merge the collected blobs into one JSON array (jq if you have it, python otherwise):
jq -s '.' collected/*.validator.json > validators.json
#   — or —
python3 -c "import json,glob; print(json.dumps([json.load(open(f)) for f in sorted(glob.glob('collected/*.validator.json'))], indent=1))" > validators.json

export HK_PROVER_URL=http://<prover-host>:9911             # ALWAYS pin a public testnet
hk-node genesis-build validators.json genesis.json
sha256sum genesis.json                                      # publish this digest + the file
```
Coordinator also runs: the seed node (stable public multiaddr), the hosted prover (vk
endpoint + proving for demo traffic), and the public explorer. **G3 soak clock**: starts
when ≥4 external validators hold ≥⅓ of voting power; 30 days incident-free.
