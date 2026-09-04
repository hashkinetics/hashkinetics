# Stablecoin rails and the cross-chain oracle — what exists, what an issuer needs, the plan

**Written 2026-09-04 (morning after K4).** Question asked: *if Circle (USDC) or Tether (USDT) wanted to deploy on HashKinetics today, what do we have — and if not enough, what is the implementation plan?* Short answer: **not enough, and the gap is well-defined.** The ledger is multi-asset by construction, but there is no way to *create* an asset after genesis, no issuer controls, no way to verify an issuer's attestation, and no bridge. This document is the inventory (with file references), the issuers' actual on-ramp as of today (researched, linked at the end), the design, and the sequence. Public-safe: nothing here is an offer of anything.

## 0 · The answer in one table

| An issuer would ask | Today | After this plan |
|---|---|---|
| Can you hold my asset next to others? | **Yes** — balances are keyed `(account, asset)`; mandates and channels carry an asset id | unchanged |
| Can I mint and burn under my own authority? | **No** — the only supply source is the genesis `alloc` table | `AssetRegister` / `AssetMint` / `AssetBurn`, issuer-scoped, per-asset supply in the state commitment |
| Can I freeze an address and pause the asset under lawful process? | **No** | `AssetFreeze` / `AssetPause`, issuer-only, receipts published |
| Can your chain mint against my attestation (xReserve / mint-bridge style)? | **No** | attested mint: issuer attestation + our bonded relayer signature (2-of-2), replay-proof deposit ids |
| Can users burn here and get USDC elsewhere? | **No** | `AssetBurn` with a destination → burn intent signed by our attestation service → issuer withdrawal |
| Do you have the off-chain service that talks to my API and my Ethereum contract? | **No** | `hk-attest`: watches both chains, submits mints, signs burn intents, idempotent, alerted |
| Can my asset enter your shielded pool? | pool is single-asset (v1) and any asset can be the pinned one | per-asset `pool_eligible` policy; multi-asset pool is P6, later |
| Which asset pays fees? | a hard-coded test asset (`FEE_ASSET = H256([9;32])`) | genesis field; HKN at mainnet; stablecoin-denominated gas is a later product feature |

## 1 · What the issuers actually offer a chain like ours (as of 2026-09-04)

**Circle.** Native USDC is Circle's decision after its blockchain due-diligence process; on EVM chains the on-ramp is the Bridged USDC Standard (a FiatToken contract Circle can take over and upgrade in place); it is explicitly EVM-only, and Circle steers non-EVM ecosystems to native issuance hubs (Noble for Cosmos, Asset Hub for Polkadot). For a sovereign non-EVM chain the realistic day-1 product is **xReserve**: Circle deploys and audits a reserve contract on Ethereum that holds USDC 1:1; the partner chain deploys *its own* USDC-backed token; a user deposits USDC into xReserve → Circle's attestation service signs a deposit attestation → the partner's attestation service fetches it and the partner chain mints; burns on the partner chain become signed *burn intents* that xReserve verifies before releasing USDC (with optional forwarding to another chain). Trust model as Circle states it: "Circle, Partner Blockchain". It is **not permissionless** — "only select blockchain teams partnered with Circle can integrate" — and the launch partners include Aleo (a privacy chain — the precedent that matters for us), Canton, Cardano, Movement and Stacks. CCTP v2 is the native-USDC cross-chain layer and comes later, if ever, at Circle's discretion.

**Tether.** Native USDT is issued on chains Tether selects; in 2026 it *wound down* support for five legacy chains, so activity and ecosystem matter more than technology. Expansion paths: native issuance on chains it picks (including a native launch on Bitcoin via RGB), USDT0 (an omnichain representation on LayerZero rails) for chains without native issuance, and USAT (its GENIUS-Act-compliant token) which on Celo has native mint/burn and can pay gas — the shape of what a chain must support.

**What both need from the chain, in common:** an asset with issuer-controlled mint and burn, address freeze and asset pause, metadata (symbol, decimals), a supply the issuer can reconcile against its reserve, an attestation-verification path, an operated attestation service, monitoring, and a compliance story for privacy features. That list *is* the plan below.

## 2 · Inventory — what exists today (file references)

- **Multi-asset ledger:** `hk-state/src/lib.rs:186` `balances: BTreeMap<(AccountId, AssetId), Amount>`; `AssetId = H256` (`hk-primitives/src/lib.rs:25`); transfers, `AccountCreate`, mandates (`MandateCreate { asset }`) and channels (`ChannelOpen { asset }`) are all asset-scoped (`hk-state/src/tx.rs`). Conservation per asset is implicit (transfers only move balances).
- **Supply creation:** genesis only — `Genesis.alloc: Vec<(AccountId, AssetId, Amount)>` (`lib.rs:68`), applied at `lib.rs:282`. No runtime issuance of any kind.
- **Fee asset:** `pub const FEE_ASSET: AssetId = H256([9u8; 32])` (`lib.rs:180`) — the staging test asset, a constant, not a genesis field.
- **Shielded pool:** single-asset, "the FIRST mint pins the pool's asset" (`tx.rs` `MintToPool`); `PoolState.asset` (`lib.rs:772`). Conservation ledger `total_shielded` in the state commitment. Disclosure (CVA) verified offline; no master view key by design.
- **Issuer controls:** none — no registry, no roles, no freeze, no pause, no metadata.
- **External attestations / bridge / oracle:** none. No secp256k1 verifier in the tree (the crypto crate is hash-based on purpose).
- **Edge:** `hk-facilitator` (x402-style paid endpoints + receipts), the compatibility shell (x402 / AP2 / MCP / ERC-8004) — all *on-chain-side* of a payment; nothing that reads another chain.
- **Explorer / wallet / RPC:** balances by asset exist in the API (`hk_balance { account, asset }`); the wallet and explorer assume the single test asset.

## 3 · Design — workstream X (stablecoin rails) and the attestation primitive

Doctrine first, because it decides the shape: **money on this chain moves only under hash-based authority.** An issuer's mint is *additionally* gated by the issuer's own attestation, in whatever algorithm the issuer uses today (Circle's attestations are classical signatures); that signature never controls a balance, an account or a vote — it only authorizes a rate-limited mint of the issuer's own liability, and it is always paired with a hash-based signature from our bonded relayer. The exception is bounded, named, and goes in the honesty ledger. A quantum break of an issuer's key is the issuer's problem, capped by its own rate limits; a quantum break of nothing on our side is possible, as before.

### X1 · Asset registry and issuer-controlled assets (consensus)

- `Tx::AssetRegister { asset, symbol, decimals, issuer: AccountId, policy }` — `asset` must equal `H(DOM_ASSET ‖ issuer ‖ symbol)` (squat-proof, like account ids). `policy { mintable, freezable, pausable, pool_eligible, attested_mint: Option<AttestationPolicy> }`. Genesis gains an `assets` table so HKN and the test asset are registered from block 0; `FEE_ASSET` becomes `genesis.fee.asset`.
- `Tx::AssetMint { asset, to, amount }` / `Tx::AssetBurn { asset, amount, destination: Option<Destination> }` — issuer-signed (mint) / holder-signed (burn). Per-asset `supply` and `burned` counters folded into the state commitment (conservation from block 0 extended to issued assets: Σ balances + pool = supply − burned, checked in tests as invariant I5').
- `Tx::AssetFreeze { asset, account, frozen: bool }` / `Tx::AssetPause { asset, paused: bool }` — issuer-only; frozen accounts cannot send that asset (mandate spends and channel opens included); paused assets cannot move at all. Every action is a receipt string the explorer shows (`frozen by issuer`, `asset paused`).
- **Consensus-breaking** (new `Tx` variants, appended last — same discipline as `AccountCreate`): nodes must be ≥ the release before the first registration commits; on testnet-1 this is a coordinated activation like the AccountCreate roll. It must land **before the audit-scope freeze** (A1) and **before the soak clock starts** — see §5.
- Size: L (3–5 days incl. tests). Files: `hk-state/src/{tx.rs, lib.rs, assets.rs(new)}`, `hk-node/src/genesis.rs`, RPC (`hk_getAsset`, `hk_getAssets`, balances listing), explorer asset view.

### X2 · Attested mint — the primitive behind every "oracle"

- `Tx::AssetMintAttested { asset, to, amount, deposit_id, issuer_attestation, relayer_sig }`, valid iff: the asset's `attested_mint` policy names the issuer attestation key(s) and algorithm; `issuer_attestation` verifies over `(domain, deposit_id, to, amount)`; `deposit_id` is unused (consumed ids live in state — replay-proof); `relayer_sig` is a hash-based signature from a **registered bonded relayer** (the `hk-attest` operator's account; bonding/slashing reuse P4 when it ships, deposit-bond at v1); the per-asset **mint rate limit** (amount per N blocks, set by the issuer at registration) is not exceeded.
- Verification of the issuer's algorithm is behind a feature flag per algorithm (`secp256k1` via RustCrypto `k256`, isolated in `hk-crypto::external` with a loud doc-comment that it is an *issuer credential verifier*, never a chain-authority primitive). Exact message format and key type are confirmed with Circle at partnership time; until then the devnet runs the same shape with a test attestation key.
- The same primitive generalizes: `source` = issuer domain today; later `source` = a bonded attestor committee for third-party bridged assets or price feeds (§4). One verification path, one registry, one honesty-ledger line.
- Size: M.

### X3 · Burn → withdrawal (the return path)

- `AssetBurn` with `destination { domain, address }` emits `Event::AssetBurned { asset, amount, destination, burn_id }`; the burn id is `H(txid ‖ index)`.
- `hk-attest` watches burn events, produces a **burn intent** in the issuer's format, signs it with the key the issuer registered for us (for xReserve that is a key verifiable on Ethereum, held in an HSM), submits it; the issuer verifies and releases funds (xReserve can forward to another chain in the same withdrawal). Receipt on our side: `hk_getBurn { burn_id }` → intent submitted / attested / released.
- Size: S (chain) + part of X4.

### X4 · `hk-attest` — the remote-blockchain attestation service (new binary, alongside `hk-facilitator`)

- Inputs: an Ethereum JSON-RPC (own node or a provider, plus a second for cross-checks), the issuer's attestation API, our own node RPC.
- Deposit path: sees an xReserve deposit for our domain → fetches Circle's attestation → submits `AssetMintAttested` with its hash-based signature. Idempotent by deposit id; retries with backoff; refuses if the asset is paused.
- Burn path: sees `AssetBurned` → signs the burn intent → submits → tracks the withdrawal attestation → writes the receipt.
- Ops: keys in HSM/systemd credentials (K2 rules), rate limits mirrored from the issuer, health endpoint, and the Discord alert bot gains three probes: attest service up, Ethereum RPC lag, mint/withdraw queue age. Runbook section for "issuer paused us".
- Size: M–L. Rust, reuses the facilitator's HTTP/receipt code.

### X5 · Shielded pool policy per asset (design note + one flag)

An issuer's freeze cannot reach a note in the pool — that is the point of the pool — so whether a stablecoin may be shielded is the issuer's call, expressed as `pool_eligible` at registration and enforced at `MintToPool`. Our compliance answer stays the one we already ship: holder-produced, single-payment, offline-verifiable disclosure (CVA), no master view key — plus per-asset pool caps if an issuer wants them (the value-cap machinery from the guarded-mainnet plan). Multi-asset pool = P6, after the soak. Size: S now (policy + flag), P6 later.

### X6 · Fees and the "gas in USDC" question

Fees stay flat and denominated in the genesis fee asset (HKN at mainnet). Paying fees in a stablecoin (what Celo does for USAT, what Circle's Paymaster does on EVM) is a fee-asset policy, not an oracle: a second fee asset with an issuer-published fixed rate, or a sponsor account that pays HKN on behalf of stablecoin users (the facilitator already has the sponsor pattern from `AccountCreate`). Decide at D7 with the fee-market spec; no code now.

### X7 · Wallet, explorer, RPC

Asset list and per-asset balances (`hk_getAssets`, `hk_balance` listing), deposit/withdraw screens in the wallet (deposit = "send USDC to this xReserve address with this memo" → watch for the mint; withdraw = burn with destination), explorer asset pages with supply, burned, frozen count, pause state, and the attested-mint receipts. Size: M (after X1–X4 land on devnet).

### X8 · Outbound proofs (the long-term oracle story, unchanged)

Other chains verifying *us* — Merkleized state (P1) + proof-of-consensus (P2) — is what turns HashKinetics from "one more attested source" into a provable one. Not needed for xReserve (Circle trusts our attestation service plus its own attestations) and not before the soak.

## 4 · "Cross-chain oracle" — what actually needs one, and the honest v1

| Need | Oracle required? | v1 mechanism | Trust label |
|---|---|---|---|
| USDC in/out | no generic oracle — the issuer attests its own deposits and verifies our burns | X2 + X4 (xReserve shape) | Circle + our bonded relayer |
| USDT / other issuer assets | same shape if the issuer offers an attested mint bridge; otherwise the issuer's chosen messaging rails must run on our chain (their endpoint, our registry) | X2 with the issuer's or the rail operator's keys | issuer (+ rail operator) |
| Third-party bridged assets (wrapped BTC, ETH) | yes — someone must attest source-chain finality | a **bonded attestor committee** (N-of-M hash-based signatures, deposit-bonded, slashable when P4 ships) using the X2 primitive with `source = committee` | committee — say so on the site |
| Price feeds | only if fees, bonds or caps become USD-denominated; nothing today needs one | the same committee, signing price rounds; or a feed network's own nodes if one deploys on us | committee / feed network |
| Our state and consensus, verified elsewhere | this is the other direction | P1 + P2 (proof-of-consensus) | mathematics, eventually |

The doctrine line for the site: *"External facts enter HashKinetics only through registered, bonded attestors whose signatures are hash-based; issuers additionally attest their own liabilities. There is no anonymous oracle and no ECDSA authority over any balance."*

## 5 · Sequence, sizes, receipts

| Step | What | Size | Receipt | Where in the sprints |
|---|---|---|---|---|
| X1 | asset registry, issuer mint/burn, freeze/pause, genesis assets, fee asset from genesis | L | devnet: register `USDC.t`, mint 1,000, freeze an account (its transfer refused with the receipt string), pause/unpause; supply/burned in `hk_getAsset`; conservation test I5' | Sprint 2 (with V1 — both consensus changes, one audit freeze) |
| X2 | attested mint + relayer registry + rate limit + `hk-crypto::external` secp256k1 verifier | M | devnet: a test attestation key mints; a replayed deposit id is refused; a mint over the rate limit is refused; a mint without the relayer signature is refused | Sprint 2 |
| X3 | burn with destination + burn receipts | S | devnet burn → event → intent JSON | Sprint 2 |
| X4 | `hk-attest` service against Ethereum Sepolia + a **mock** of the issuer's attestation API with the published message shapes | M–L | Sepolia deposit → devnet mint in < 2 min unattended; devnet burn → intent accepted by the mock; kill −9 the service mid-flow → no double mint | Sprint 3 |
| roll | activation on testnet-1 (coordinated, R7 discipline, `≥ vX before the first AssetRegister`) | S | testnet-1 has `USDC.t` registered by a test issuer; explorer asset page live | **before the soak clock starts** |
| X5/X7 | pool policy flag; wallet + explorer asset UX | S + M | wallet shows two balances; deposit/withdraw screens against Sepolia | Sprint 3–4 |
| partner | Circle xReserve partnership conversation (permissioned); Tether contact | founder | our domain registered on xReserve testnet; real attestation key replaces the mock | founder lane, start now |
| receipt | end-to-end on testnet-1 with Circle's testnet: Sepolia USDC → `USDC.hk` → burn → Sepolia USDC | — | the demo video and the receipts page entry | after partnership |

**Engineering total:** ~3 weeks of chain + service work, most of it parallel to V1/R11. **The one scheduling truth:** X1–X3 change consensus, so they must be on testnet-1 *before* the 30-day soak starts and inside the audit-scope freeze; doing them now costs ~2 weeks of Sprint 2–3 capacity and saves a second consensus roll (and a soak restart) later. Recommended.

## 6 · What only the founder can do

1. **Circle:** the xReserve conversation (partner programme; Aleo is the precedent to cite — privacy chain, USDC-backed token) and, in parallel, the Bridged-USDC/native-USDC due-diligence contact. Ask for: the remote-blockchain integration spec (attestation format, key type, domain registration, rate-limit expectations, testnet access).
2. **Tether:** an expansion conversation once testnet activity is visible (they select on activity); ask which rail they would use for a non-EVM chain (native vs USDT0-style).
3. **Infrastructure:** an Ethereum RPC pair (own node preferred), an HSM or systemd-credential path for the attestation key, and a budget line (the use-of-funds already carries $100–150K for "cross-chain oracle + bridge").
4. **Policy:** decide the pool eligibility default for issuer assets (my recommendation: off by default, on per issuer agreement) and whether third-party bridged assets are in scope for mainnet at all (my recommendation: no — stablecoins first).

## 7 · Honesty ledger additions

- Issued assets and attested mints: **designed, not built** (this document).
- Stablecoin availability depends on issuer partnership decisions we do not control; until then every stablecoin on testnet-1 is a test asset.
- The only classical signature the chain will ever verify is an issuer's attestation over its own liability, always paired with a hash-based relayer signature and a rate limit; it is named in the doctrine line above.
- Third-party bridged assets, if ever, ride a bonded committee and are labeled as such.

## Sources (researched 2026-09-04)

- Circle, Bridged USDC Standard — EVM-only, Circle's option to upgrade, due-diligence process, Cosmos/Polkadot guidance: https://www.circle.com/bridged-usdc
- Circle, xReserve — Circle-deployed reserve, partner-deployed token, attestation flows, permissioned partnership, launch partners: https://www.circle.com/xreserve and https://developers.circle.com/xreserve/concepts/how-xreserve-works.md
- Circle developer index (CCTP v2 guidance, Gateway/x402 nanopayments, xReserve docs): https://developers.circle.com/llms.txt
- Tether, wind-down of five legacy chains (selection on activity): https://tether.io/news/tether-to-wind-down-usdt-support-for-five-legacy-blockchains-as-part-of-strategic-infrastructure-review/
- Tether USAT on Celo (native mint/burn, gas in USAT): https://coinpaprika.com/news/tether-usat-beyond-ethereum-celo/
- Tether native USDT on Bitcoin via RGB: https://www.kucoin.com/news/flash/tether-to-launch-native-usdt-on-bitcoin-network-via-rgb-protocol
