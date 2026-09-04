# X1 — issued assets: registry + issuer controls (mint · burn · freeze · pause)

**Status: implemented 2026-09-04 (v0.15.0); hk-state tests 21/21; devnet gate `chain/gate-x1.sh` 40/40 GREEN; released and rolled to every testnet-1 seat (R7, state-compatible — the registry enters the commitment only once non-empty). Activation on testnet-1 is the first asset transaction: from that block every node must be ≥ v0.15.0. Must land before the audit-scope freeze (A1) and before the soak clock starts — P3.2 §X.** Companion: `docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md` (why an issuer needs exactly these five verbs on day one; X2 attested mint builds on this).

## 1 · What changes

Until now an asset on HashKinetics was a 32-byte label with no owner: the only supply source was the genesis `alloc` table, the protocol-fee asset was a hard-coded constant, and nothing on the chain could mint, burn, freeze or pause anything. An issuer (Circle's xReserve partner flow, Tether, any regulated stablecoin) cannot deploy on such a chain — their minimum is: **they mint against reserves, they burn on redemption, they can freeze a sanctioned account and pause the asset in an incident, and they can prove supply.**

X1 adds an **asset registry** to the state machine. A registered asset has an issuer, a policy fixed at registration, per-asset supply and burn counters folded into the state commitment, and issuer-only control transactions. **Unregistered assets keep behaving exactly as today** — testnet-1's native asset is unregistered and nothing about it changes.

## 2 · The rule

**Identity.** `asset = H(DOM_ASSET_ID ‖ issuer ‖ symbol)` with `DOM_ASSET_ID = "hk/v1/asset-id"`. The registering transaction's sender IS the issuer, so an id can only be claimed by the account it names — squat-proof by construction, exactly like account ids (`H(DOM_ACCOUNT_ID ‖ auth_commit)`). Two issuers may both register the symbol `USDC`; they get different ids and wallets show issuer + symbol. Genesis may register assets under **any** id (genesis is the trust root) — that is how a network registers its native asset.

**Symbol**: 1–16 bytes of `[A-Za-z0-9._-]`, first byte a letter. **Decimals** ≤ 18 (display only; the state machine moves base units).

**Policy** (fixed at registration in X1 — no policy or issuer changes on-chain; see §7):

| flag | meaning |
|---|---|
| `mintable` | the issuer may `AssetMint` |
| `freezable` | the issuer may `AssetFreeze` individual accounts |
| `pausable` | the issuer may `AssetPause` the whole asset |
| `pool_eligible` | the asset may be shielded (`MintToPool`); issuer freeze can never reach a note, so an issuer that needs reachability sets this to `false` — the answer to the compliance question before it is asked (X5) |

**Transactions** (appended AFTER `AccountCreate` — bincode variant tags of every existing transaction are untouched):

| tx | who | effect |
|---|---|---|
| `AssetRegister { asset, symbol, decimals, policy }` | anyone (becomes issuer) | registry entry; refused if the id is not `H(DOM_ASSET_ID ‖ sender ‖ symbol)`, already registered, symbol/decimals invalid |
| `AssetMint { asset, to, amount }` | issuer, `mintable` | `supply += amount`, credit `to`; refused when paused or `to` is frozen |
| `AssetBurn { asset, amount, destination }` | any holder | debit sender, `burned += amount`; `destination` (≤ 64 bytes, opaque) is the redemption target an issuer's return path reads (X3 defines formats); refused when paused or sender frozen |
| `AssetFreeze { asset, account, frozen }` | issuer, `freezable` | account enters/leaves the asset's frozen set |
| `AssetPause { asset, paused }` | issuer, `pausable` | asset enters/leaves the paused state |

**Gates — where the policy bites.** Every movement of a **registered** asset passes one gate: refused with `asset paused` while the asset is paused; refused with `frozen by issuer` when the account money leaves **or** the account money reaches is frozen. The gate sits at every balance move in the state machine: `Transfer`, the funding leg of `AccountCreate`, `MandateSpend` (the ROOT funding account is the payer), `ChannelOpen` (escrow leaves the funder), `ChannelSettle` (escrow reaches the payee), `ChannelRefund` (escrow returns to the payer), `MintToPool` (also requires `pool_eligible`), the transparent fee leg of `ShieldedSpend` (the unshield credit), `AssetMint`, `AssetBurn`. A refusal is a normal receipt: the transaction costs its envelope fee like any other refusal and mutates nothing.

**What the gate does not touch.** The protocol envelope fee is charged in the network's fee asset by consensus, before dispatch; it is not an issuer-controlled movement. A network that registers its fee asset in genesis must give it `pausable = false, freezable = false` — a genesis that says otherwise is refused at load (`fee asset policy`), so an issuer key can never pause the chain's fee path.

**Supply accounting.** `supply` counts everything ever minted (genesis allocations of a genesis-registered asset included), `burned` counts `AssetBurn` only. Conservation for a registered asset (invariant **I5'**, tested):

```
Σ balances(asset) + Σ open-channel escrow(asset) + pool.total_shielded (if the pool's asset)
  = supply − burned − fees_burned (the last term for the fee asset only)
```

## 3 · Commitment, snapshot, wire — why a rolling upgrade cannot fork

- **State commitment.** The registry enters `C(Σ)` **only once it is non-empty** (tag `0xA5`, then count, then each asset's id ‖ issuer ‖ symbol ‖ decimals ‖ policy bits ‖ paused ‖ supply ‖ burned ‖ frozen set — a fixed byte layout, no JSON). With an empty registry the buffer is byte-identical to v0.14's, so v0.14 and v0.15 nodes agree on every block until the first registration commits. Same trick as the fee counter in v0.12.
- **Snapshot.** `StateSnapshot` gains `assets` as its last field; the node writes `snapshot3.bin` and still reads `snapshot2.bin`/`snapshot.bin` (the file name is the version tag; restore picks the highest height). A v2 snapshot restores with an empty registry; if the network's genesis registers assets, the recomputed commitment would not match the recorded one and the node refuses to run — resync from genesis, never a silent divergence.
- **Wire.** New `Tx` and `Event` variants are appended last. **Activation rule, as for `AccountCreate` (v0.11.0) and V1 (v0.14.0): every node must run ≥ v0.15.0 before the first asset transaction commits.** A v0.14 node cannot decode that block, applies an empty batch, diverges on the parent commitment and halts — loudly, by design. Minimum node version for testnet-1 becomes v0.15.0 at that moment.
- **Genesis.** `chain.assets = [{ id, symbol, decimals, issuer, policy }]` (absent on testnet-1 — its genesis bytes, hence its chain id, are unchanged) and `chain.fee.asset` (absent = the historical constant `H256([9; 32])`). `hk-node genesis-build --asset SYMBOL:DECIMALS:ISSUER-AUTH0:FLAGS` registers an asset from block 0; `--fee-asset` names the fee asset.

## 4 · Operator / integrator surface

- RPC: `hk_getAsset {asset | issuer+symbol}` → registry entry + supply/burned/paused; `hk_getAssets` → the whole registry; `hk_getAccount` gains `balances: [{asset, amount}]`; block/explorer summaries name the five kinds (`asset_register`, `asset_mint`, `asset_burn`, `asset_freeze`, `asset_pause`).
- CLI: `hk-node asset-id <ISSUER-hex> <SYMBOL>` (offline) · `hk-node asset register|mint|burn|freeze|pause <DIR> <RPC> …` — signed with the DIR's self-custodied account through the same reserve-then-sign path as `account-send`.
- Devnet gate `chain/gate-x1.sh`: register `USDC.t` → mint → transfer → freeze (transfer refused `frozen by issuer`) → unfreeze → pause (every move refused `asset paused`) → unpause → burn with destination → conservation via RPC → restart restores `snapshot3.bin` → a fresh node syncs from genesis across the registration.

## 5 · What X1 deliberately leaves out

- **No attested mint.** Every mint is issuer-signed; the attestation + bonded-relayer primitive is X2 and reuses this registry.
- **No policy or issuer change after registration.** An issuer that needs a key rotation registers under a fresh id or waits for the governance path (P-lane).
- **No burn receipts endpoint** (`hk_getBurn`) and no destination format — X3.
- **No multi-asset pool.** The pool still pins one asset; `pool_eligible` governs whether an asset may be that asset.
- **Fees stay in one asset** (X6 discusses "gas in USDC").

## 6 · Files

`chain/crates/hk-state/src/assets.rs` (registry types, id derivation, validation, commitment bytes) · `hk-state/src/tx.rs` (five variants) · `hk-state/src/lib.rs` (registry in `State`, dispatch, gates, genesis, snapshot, commitment) · `hk-state/src/tests.rs` (`x1_*`: receipts, conservation, wire compatibility, commitment stability) · `hk-node/src/store.rs` (`snapshot3.bin`) · `hk-node/src/rpc.rs` · `hk-node/src/main.rs` + `account.rs` (CLI) · `chain/gate-x1.sh`.

## 7 · Honesty

Issuer controls are **issuer-signed transactions**, not oracles: the chain enforces who may call them and records every call; it cannot judge whether a freeze was lawful. Freezing an account stops that account's transparent movements of that asset only — notes already in the shielded pool are unreachable by design (that is what `pool_eligible = false` is for). The registry is a testnet governance surface: mainnet issuers will hold their keys in HSMs (K2) and mint through the attested path (X2), and the five verbs here are the floor an issuer expects, not a compliance product.
