# The protocol fee — normative reference (v0.15.0 · testnet-1)

**One flat fee per transaction envelope, bound into the genesis, burned.** On testnet-1: **100 micro** (0.000100 test units) from **height 1**. This page is what a wallet, an exchange integration, an agent framework or an auditor needs; the consensus rule itself is `YELLOWPAPER.md` §19.2–19.3 and `chain/crates/hk-state/src/lib.rs` (`apply_signed`).

## The rule in one paragraph

Every signed envelope applied at height `h ≥ fee.from_height` is charged `fee.micro` of the fee asset (`0909…09`, the transparent test unit on testnet-1; since v0.15.0 a genesis may name another via `chain.fee.asset`) **before** its payload runs. If the payload is refused, the fee is credited back and the state is exactly as before — a refused transaction never moves money, fee included. If the payload succeeds, the fee is **burned**: debited from the sender and credited nowhere; the cumulative burn is `fees_burned`, part of the state commitment. Nobody earns the fee on testnet-1. The account's one-time key ratchet advances only on success, so a refused envelope costs neither money nor a key index.

## What this means in practice

| Situation | Outcome |
|---|---|
| Send `amount` with balance `≥ amount + 100` | payload applied, `100` burned, balance = old − amount − 100 |
| Send your **whole** balance | refused: `rejected: insufficient balance: have <balance−100>, need <balance>` — the fee was debited first, the transfer saw the post-fee balance, the fee was refunded. **`max` = balance − fee.** The Windows wallet computes this for you and refuses locally before signing (so no ratchet index is spent on a doomed envelope) |
| Balance `< 100` | refused before anything else: `rejected: insufficient balance for the protocol fee (have <a>, need 100)` |
| Shield / unshield / shielded pay | the envelope fee is paid from the **transparent** balance of the account that signs the envelope, exactly like a transfer; the pool's own conservation (`in = out₁ + out₂ + pool_fee`) is separate and unchanged |
| Mandate spend, channel open/settle, account creation | same envelope fee; the sponsor of an `AccountCreate` pays it |
| The faucet drip | the faucet's treasury pays the fee (its `/health` reports `fee`) — a drip of 100,000 micro costs the treasury 100,100 |

## Where the number comes from — and why you cannot change it

`genesis.json` carries `chain.fee = {"micro": 100, "from_height": 1}` (U4.b). A node reads it at start and **ignores** any local `HK_FEE_MICRO` / `HK_FEE_FROM`, logging that the override was refused. Because the chain id is derived from the genesis digest, a validator cannot run a different fee schedule without being on a different network. Networks whose genesis has no `fee` field (staging-1 and earlier) fall back to the v0.12 behaviour: local configuration decides, default activation height 110,000 — that path exists for old devnets only.

How the policy reaches the genesis: `hk-node genesis-build validators.json genesis.json --fee-micro 100 --fee-from 1 …` (`docs/CEREMONY-TESTNET-1.md`). `--fee-micro 0` (or omitting the flags) builds a fee-free genesis.

## Observing it

- `hk_chainInfo.fee` → `{"micro":"100","from_height":1,"burned_micro":"<cumulative>"}` — the burn counter is a live, chain-wide number (`docs/RPC.md`).
- The explorer's fee tile shows the same counter; every transaction's receipt is visible on its block.
- `faucet.hashkinetics.org/health` reports the fee alongside the drip size.

## What the fee is not

Not a fee market (no priority, no bidding — the mempool is first-come within the nonce window), not validator revenue (burned), not a price signal (test units have no monetary value). It is an anti-spam floor and a full rehearsal of the fee mechanics — charge, refund-on-refusal, burn, commitment — so that the mainnet fee design (`WHITEPAPER.md`; the planned validator/treasury split is a **plan**, labeled as such wherever it appears) lands on code that has already run in public.

## History

- v0.12.0/0.12.1 (2026-09-02) — first cut, activation by local config at a fixed height; the accompanying R10 memory change broke restore on a live validator and the roll was aborted.
- v0.12.2 (2026-09-02, one voter at a time) — fee + R9 shipped without R10; `fees_burned` enters `C(Σ)` only once nonzero so the rolling upgrade could not fork before activation.
- v0.15.0 (2026-09-04) — `chain.fee.asset` (X1): the fee asset is a genesis field too (absent = the historical constant, so testnet-1's genesis bytes are unchanged). The fee leg is a protocol movement and is NOT subject to issuer controls: a genesis that registers its fee asset as pausable or freezable is refused at load, so no issuer key can pause the chain's fee path (`docs/X1-ISSUED-ASSETS.md`). Fee burns of a registered fee asset are accounted in `fees_burned` and subtracted in that asset's conservation identity.
- v0.13.0 (2026-09-02 evening) — the policy became a genesis fact; testnet-1 burns from block 1. The first burned fee on the public chain was the first faucet drip (an `AccountCreate` paid by the treasury) within the first hour; `burned_micro = 900` (nine envelopes) at height 15,897 on 2026-09-03 morning.
