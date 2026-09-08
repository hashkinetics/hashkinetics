# B1 — Sepolia USDC ↔ testnet-1 bridge: implementation plan

**Written 2026-09-09 (Yadu: "make an oracle cross-chain bridge — USDC on Sepolia with our testnet: mint here / lock there, lock here / mint there — implementation plan first").** This is the concrete build plan for the first bridge, on testnets only. It sits inside the design already written in `docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md` (2026-09-04): X1 (issued assets) shipped in v0.15.0 and is live on testnet-1; X2 (attested mint with on-chain deposit ids), X3 (burn → withdrawal) and X4 (`hk-attest`) are not built. **B1 is X3 + X4 against Ethereum Sepolia with a plain X1 mint**, and it produces the receipts that make the X2 and the Circle conversations concrete. Public-safe: nothing here is an offer; every number is labeled.

## 0 · What gets built, in one paragraph

A vault contract on Ethereum Sepolia holds Circle's testnet USDC. A user locks USDC in the vault naming a HashKinetics account; an attestation service we run (`hk-attest`) waits for Sepolia finality and mints the same amount of an issued asset `USDC.sep` on testnet-1 to that account. The other way: a user burns `USDC.sep` on testnet-1 with a Sepolia address as the burn destination; `hk-attest` sees the committed burn and signs an unlock that the vault verifies before releasing USDC. The asset is registered pool-eligible, so bridged USDC can be shielded and paid privately — the demo that matters — **on a devnet now, and on testnet-1 only after the multi-asset pool (P6): the v1 pool is single-asset and testnet-1's is already pinned to the test asset (`hk-state/lib.rs` "the first mint pins the asset").** Trust label, stated everywhere: **on the HashKinetics side every balance moves under hash-based authority; on the Ethereum side the vault trusts a threshold of attestor keys, which are ECDSA because Ethereum verifies nothing else. The bridge is exactly as safe as those keys and the attestor's code.**

## 1 · Facts the design stands on (verified 2026-09-09)

| Fact | Value | Source |
|---|---|---|
| Sepolia USDC (Circle testnet) | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, 6 decimals, chain id 11155111 | Circle docs / Etherscan (sources below) |
| Testnet USDC faucet | faucet.circle.com — 20 USDC per address per 2 hours | Circle |
| Sepolia finality | PoS: a block is *finalized* after two epochs (≈ 12.8 min); *safe* after ≈ one | Ethereum consensus |
| HK issued assets (X1, live since v0.15.0) | `AssetRegister {symbol, decimals, policy m/f/p/s}` · `AssetMint {to, amount}` (issuer-signed) · `AssetBurn {amount, destination ≤ 64 bytes}` (holder-signed) · freeze / pause · per-asset `supply` and `burned` in the state commitment · `hk_getAsset`, `hk_getAssets`, `hk_balance {account, asset}` | `chain/crates/hk-state/src/{tx.rs, assets.rs}`, `docs/X1-ISSUED-ASSETS.md`, `chain/gate-x1.sh` |
| HK CLI | `hk-node asset register <DIR> <RPC> <SYMBOL> <DECIMALS> <FLAGS>` · `mint <DIR> <RPC> <ASSET> <TO> <MICRO>` · `burn <DIR> <RPC> <ASSET> <MICRO> [DESTINATION-hex]` — signs with the account directory's hash-based key state | `chain/crates/hk-node/src/account.rs` |
| Watching HK | `hk_getBlock` → `txs[{txid, sender, kind, fields, receipt}]` with `kind = asset_burn` and `fields.destination`; commit = finality (BFT), 1.0 s floor since v0.18.2 | `docs/RPC.md` |
| Asset id | `H(DOM_ASSET_ID ‖ issuer ‖ symbol)` — squat-proof; `USDC.sep` under the bridge issuer account is unique | `hk-state/assets.rs::derive_asset_id` |
| Amounts | HK "micro" = 6 decimals = USDC's 6 decimals → 1:1, no scaling | — |
| Shielded pool | single-asset in v1; the first `MintToPool` pins the pool's asset — testnet-1's pool is pinned to the test asset, so `USDC.sep` shields on a fresh devnet only until P6 (multi-asset pool) | `hk-state/src/lib.rs` (`PoolAssetMismatch`), oracle plan X5 |
| Mint recipient | `AssetMint` credits any 32-byte id — the chain does not check the account exists; a mistyped id is an unreachable balance | `hk-state/src/lib.rs::do_asset_mint` |
| Fee on HK | every envelope pays 100 micro of the genesis fee asset (the test asset) — a freshly credited `USDC.sep` holder cannot move it until it also holds fee asset | `docs/FEES.md` |
| Ethereum tooling | Solidity 0.8.x + OpenZeppelin 5 (SafeERC20, Pausable, Ownable2Step, ReentrancyGuard, EIP-712/ECDSA) with Foundry; relayer in Rust with `alloy` | standard |

## 2 · Architecture

```
  Ethereum Sepolia                          hk-attest (Rust service, we run it)                     HashKinetics testnet-1
  ┌──────────────────────┐   lock event      ┌──────────────────────────────────────┐   AssetMint       ┌──────────────────────┐
  │ HKVault.sol           │ ───────────────▶ │ sepolia watcher  ─▶ finality gate     │ ───────────────▶ │ asset USDC.sep        │
  │  lock(amount, hkAcct) │                  │   ─▶ hk submitter (issuer key, serial)│                  │  issuer = bridge acct │
  │  unlock(to, amt, id,  │ ◀─────────────── │ hk watcher (asset_burn, USDC.sep)     │ ◀─────────────── │  policy m f p s       │
  │    sigs[])  t-of-n    │   unlock tx      │   ─▶ attestor signer(s) (EIP-712)     │  hk_getBlock      │  burn(dest = 0x…20B)  │
  │  cap · pause · owner  │                  │ sqlite ledger · idempotent · health   │                  │                       │
  └──────────────────────┘                  └──────────────────────────────────────┘                  └──────────────────────┘
        USDC 0x1c7D…C7238                       one deposit id → at most one mint                          supply == vault balance
```

- **`HKVault.sol` (Sepolia).** Holds USDC. `lock(uint256 amount, bytes32 hkAccount)` pulls USDC (`safeTransferFrom`), increments `lockNonce`, emits `Locked(depositId, sender, amount, hkAccount)` with `depositId = keccak256(chainid, address(this), lockNonce)`. `unlock(address to, uint256 amount, bytes32 burnId, bytes[] sigs)` verifies `threshold` EIP-712 signatures from the `attestors` set over `(to, amount, burnId)`, refuses a `burnId` already processed, enforces a per-day unlock cap, then `safeTransfer`. `pause()/unpause()` (owner, and any single attestor may pause — the emergency brake is cheap, unpausing is not), `setAttestors(addresses, threshold)` (owner, 2-step), `setCap`. No upgradeability in the POC (redeploy is fine on a testnet); no admin path to move funds except `unlock`.
- **`USDC.sep` (testnet-1).** Registered by the bridge issuer account with flags `mfps` (mintable, freezable, pausable, pool-eligible). `supply − burned` must equal the vault's USDC balance at every reconciliation — the invariant the service checks and the explorer can show.
- **`hk-attest` (new crate `chain/crates/hk-attest`, one binary).** Two watchers, two submitters, one ledger:
  - *Sepolia → HK:* subscribe/poll `Locked` events; a deposit is *eligible* when its block is `finalized` (configurable: `--confirm finalized | safe | N`); check the HK recipient account exists (`hk_getAccount`) — if not, hold it as `pending_recipient` and retry; submit `AssetMint {USDC.sep, to, amount}` through the issuer account key (serialised — the L-ratchet is stateful; one in flight at a time); record `deposit_id → hk_txid` before the receipt is even read (write-ahead), confirm with `hk_getTx`.
  - *HK → Sepolia:* poll `hk_getBlock` from the last processed height; for every `asset_burn` of `USDC.sep` whose destination is exactly 20 bytes, the `burnId = txid`; produce the EIP-712 attestation, collect `threshold` signatures (POC: the service holds 1 key; the second attestor is a separate process with its own key, so the code path is t-of-n from day one), submit `unlock`; record `burnId → eth_txhash`.
  - *Ledger:* sqlite, one row per deposit and per burn with state machine `seen → eligible → submitted → confirmed | held | failed`; idempotent on restart; `kill -9` at any point must never double-mint or double-unlock (the write-ahead row + the vault's `processed[burnId]` + the HK receipt make that true).
  - *Ops:* keys via systemd credentials (K2 rules: the issuer account directory sealed; the attestor ECDSA key in an env credential, never in the tree); `/health` with lag per chain and queue ages; the Discord bot gains a probe (`bridge: sepolia lag Xs · hk lag Ys · pending N`); reconciliation every 10 min: `vault.balanceOf == supply − burned`, alert on drift.
- **Wallet / explorer (thin).** The explorer's asset page already shows supply/burned/paused (X1); the CLI does burns with a destination today. A `/bridge` page on the site (MetaMask via viem: approve + lock; a field for the HK account id) is Phase 2 — the CLI loop is the receipt, the page is the demo.

## 3 · The flows, step by step

**Sepolia → testnet-1 (lock there, mint here).** (1) User has USDC from the faucet and an HK account (the wallet creates one). (2) `approve(vault, amount)`, `lock(amount, hkAccount)`. (3) After finality (~13 min at `finalized`; ~2.5 min at 12 confirmations for the demo) `hk-attest` mints `USDC.sep` to the account. (4) The user sees the balance in `hk_balance`/the wallet; on a devnet it can be shielded (`MintToPool`) and paid privately; on testnet-1 it stays transparent until P6. Failure modes: recipient account missing → held, listed on `/health`, retried; HK mint refused (asset paused, recipient frozen) → held with the receipt string; Sepolia reorg before finality → never eligible.

**testnet-1 → Sepolia (lock/burn here, unlock there).** (1) User burns: `hk-node asset burn <DIR> <RPC> <USDC.sep> <MICRO> <20-byte Sepolia address>`. (2) The burn commits (1 s); `supply` falls, `burned` rises. (3) `hk-attest` attests `(to, amount, burnId = txid)` and calls `unlock`. (4) The vault checks threshold, replay, cap, pause → USDC to the address. Failure modes: bad destination length → burn is valid on HK but *unbridgeable* — the service logs it and the docs say "exactly 20 bytes"; refund of an unbridgeable burn is an issuer decision (mint back), never automatic; vault paused → queued; cap hit → queued to the next day.

**"Lock here, mint there" (HK asset → an ERC-20 on Sepolia).** The same service and a second contract `HKWrapped.sol` (mintable ERC-20, minter = the vault's attestor set): user *burns-with-destination* on HK (the X1 primitive is burn, and a locked balance the issuer cannot touch is the same thing economically — a "lock" on HK is a burn we promise to re-mint), the service mints wHKN/wUSDC.sep on Sepolia; burn on Sepolia → mint on HK. **In scope on testnet (Yadu, 2026-09-09: "we need to build everything before mainnet — that is what the testnet is for; Sepolia gas and testnet USDC have no value, nothing is at harm").** So B1 builds both legs: `wHKT.sep` — the wrapped *test* asset on Sepolia (`HKWrapped.sol`, mintable ERC-20, minter = the same attestor set) — and the reverse burn. What stays a mainnet-time decision is only the *policy* of wrapping the real HKN on Ethereum after TGE (a securities question for counsel), not the machinery, which will already exist and be rehearsed.

## 4 · Trust model and security — said plainly

- **What is trusted.** The attestor keys (t of n) and the `hk-attest` code. A stolen threshold of keys drains the vault (Sepolia side) or mints unbacked `USDC.sep` (HK side). This is the failure mode of every attested bridge in history (Ronin, Wormhole, Nomad were exactly attestor/verification failures). Mitigations in the POC: threshold keys on separate machines, per-day caps, one-key pause, reconciliation alerts, the issuer's `AssetPause` on HK as the second brake, and *testnet value only*.
- **What is not trusted.** Nothing on the HK side moves under an ECDSA key: the mint is signed by the bridge issuer's hash-based account key, the burn by the holder's. The ECDSA exception is confined to the Ethereum contract, which is the Ethereum rule, not ours. This is the honesty-ledger line from the oracle plan §3 — B1 is its first instance; say so on the site.
- **Replay.** Sepolia: `processed[burnId]`. HK: the POC has no on-chain deposit id (plain `AssetMint`), so a replayed deposit is refused by the service's ledger only — a second `hk-attest` instance with the issuer key could double-mint. That is why X2 (`AssetMintAttested` with consumed deposit ids in state) is the mainnet shape; B1 records every `deposit_id ↔ hk_txid` pair in a public receipts file until then.
- **Finality.** Sepolia `finalized` is the default; anything faster is a demo setting and labeled. HK commit is final; the service treats a committed block as final and never rewrites.
- **Audit.** The vault and the service join the CertiK scope only if they are meant for mainnet value; the POC is explicitly out of the frozen tag `audit-2026-09` and stays a testnet feature until audited.
- **Trust-minimised path (the roadmap, not the POC).** Sepolia → HK without an attestor: HK verifies Ethereum finality itself with an SP1-Helios proof — HK nodes already verify SP1 STARKs in-node, so a proven Ethereum light-client update is a natural `AssetMintAttested` source. HK → Ethereum without an attestor: an SP1 program that verifies our commit certificate (LMS/HSS, SHAKE-256 — too expensive to do natively in the EVM) and a Groth16/PLONK verifier on Ethereum (~300k gas). That is P2 "proof-of-consensus" pointed at Ethereum. Weeks, not days; after the seat sale and the audit.

## 5 · Phases, sizes, receipts

| Phase | What | Size | Receipt (the gate) |
|---|---|---|---|
| **B1.0 — contract** | `HKVault.sol` + Foundry tests (lock/unlock/threshold/replay/cap/pause/attestor rotation); deploy to Sepolia; verify source on Etherscan | 1–2 days | `forge test` green; vault address + verified source; 20 USDC locked by hand, event seen |
| **B1.1 — asset** | bridge issuer account on testnet-1; register `USDC.sep` (6 decimals, `mfps`); explorer shows it | ½ day | `hk_getAsset` by `symbol@issuer`; the registration txid |
| **B1.2 — service** | `hk-attest`: both watchers, both submitters, sqlite ledger, finality gate, held states, `/health`, systemd unit + credentials, Discord probe, reconciliation | 3–4 days | `chain/gate-b1.sh` on a devnet + a local `anvil` chain: lock → mint (< 2 min at 12 confs), `MintToPool` of the bridged asset → a shielded payment → unshield, burn → unlock, replayed deposit refused, replayed burn refused by the vault, `kill -9` mid-flow → no double mint/unlock, vault paused → queued then drained, `supply − burned == vault balance` |
| **B1.3 — testnet-1 loop** | run against Sepolia + testnet-1 from the gateway host (or a separate small VM); the first real loop, both directions (transparent `USDC.sep` on testnet-1; the shielded leg is the devnet gate's) | 1 day | receipts: Sepolia lock tx → HK mint txid → transfer → burn → Sepolia unlock tx; `docs/BRIDGE-GUIDE.md`; the receipts page entry; #testnet announcement |
| **B1.4 — reverse leg** | `HKWrapped.sol` (ERC-20 `wHKT.sep`, 6 decimals, mint/burn by the attestor set) on Sepolia; HK burn-with-destination of the test asset → Sepolia mint; Sepolia burn(hkAccount) → HK re-mint by the bridge issuer (the test asset is genesis-allocated, not issuer-mintable — so the reverse leg re-credits from a bridge-held float, or wraps an issued asset; see §7) | 1–2 days | the loop both ways on the devnet gate, then testnet-1 |
| **B1.5 — page** | `/bridge` on the site (viem/wagmi: approve, lock, status by deposit id; burn instructions) | 1–2 days | a stranger bridges 5 USDC from the page |
| **B2 (later)** | X2 `AssetMintAttested` (deposit ids on-chain; attestor registry with hash-based relayer signature); attestor committee = founding operators (3-of-5); Circle xReserve conversation with B1 as the exhibit | 1–2 weeks | devnet gate + the roll (consensus change → before the soak) |
| **B3 (roadmap)** | SP1-Helios verified in-node (Sepolia → HK without attestors); SP1 proof of HK certificates on Ethereum | weeks | the light-client bridge |

Engineering total for B1.0–B1.3: **about one week**, most of it the service. Nothing consensus-breaking — X1 already carries everything the chain needs, so no roll, no activation height, no soak impact.

## 6 · What only the founder does

1. **Keys.** The deployer EOA for Sepolia (funded with Sepolia ETH), the attestor ECDSA key(s) — generated by you, held as systemd credentials on the service host; the bridge issuer account on testnet-1 (created with `hk-node account-new`, sealed like the fleet's keys). I never type or see any of them.
2. **RPC.** A Sepolia provider (Alchemy/Infura free tier is fine for the POC; two providers for cross-checks per the X4 design) — the URL is a credential.
3. **Policy.** `pool_eligible` for `USDC.sep`: **yes** (shielded USDC is the point — live on the devnet gate now, on testnet-1 after P6); per-day unlock cap (suggest 1,000 USDC on testnet); whether the two attestor keys are both ours at first (yes) and when a founding operator becomes the second (B2).
4. **Naming.** Symbol `USDC.sep` (says what it is: Sepolia-backed test USDC); never `USDC` alone — Circle's trademark and the honesty rule.

## 7 · Not doing (and why)

- Wrapping the *real* HKN on Ethereum is a policy decision for TGE (counsel); the machinery is built and rehearsed on testnet with the test asset (B1.4). Note for B1.4: the test asset is genesis-allocated with no issuer, so "lock here → mint there → burn there → unlock here" for it means the bridge account *holds* the locked balance (a transparent transfer to the bridge account with a memo, released on the way back) rather than an issuer mint; for issued assets (`USDC.sep` itself, or a future `HKN`) the issuer-mint path applies.
- No upgradeable proxy on the vault (testnet: redeploy; mainnet: decide with the audit).
- No general message bridge, no price oracle — B1 moves one asset in two directions; the "oracle" is the attestor, and it attests finality, nothing else.
- No mainnet value through this path until X2 + audit + a real committee.

## Sources (2026-09-09)

- [Circle — USDC contract addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses) · [Etherscan Sepolia — USDC token](https://sepolia.etherscan.io/token/0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238) · [Circle faucet limits (via MEXC learn)](https://www.mexc.com/learn/article/usdc-faucet-how-to-get-free-testnet-usdc-across-multiple-networks/1)
- [succinctlabs/sp1-helios — on-chain Ethereum light client built with SP1](https://github.com/succinctlabs/sp1-helios) · [OpenZeppelin — SP1 Helios audit](https://www.openzeppelin.com/news/sp1-helios-audit)
- In-tree: `docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md` (X1–X8, the doctrine line), `docs/X1-ISSUED-ASSETS.md`, `chain/gate-x1.sh`, `docs/RPC.md`, `docs/FEES.md`.
