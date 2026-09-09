# Bridge guide — Sepolia USDC ↔ testnet-1 (B1, testnet only)

**What this is.** A vault on Ethereum Sepolia holds Circle's testnet USDC. Lock USDC there naming a HashKinetics account and, once Sepolia has *finalized* the block (≈ 13 min), the bridge mints the same amount of the issued asset `USDC.sep` to that account on testnet-1. Burn `USDC.sep` on testnet-1 with a Sepolia address as the destination and the vault releases the USDC to it within a couple of minutes. Both legs are 1:1, 6 decimals both sides, no fee taken by the bridge (you pay Sepolia gas on the way in and the flat 100-micro protocol fee on the way out). Test value only — nothing here has a price, and nothing here is an offer.

**Trust label, said first.** On the HashKinetics side every balance moves under hash-based authority: the mint is signed by the bridge issuer account's key, your burn by yours. On the Ethereum side the vault trusts a threshold of attestor keys, which are ECDSA because Ethereum verifies nothing else. Today that threshold is **1 of 1**, and the key is run by the founders on the gateway host: the bridge is exactly as safe as that key and the attestation service's code. The next steps — deposit ids checked by consensus (X2) and a committee of founding operators (B2) — are on the [backlog](BACKLOG.md); the plan is [BRIDGE-SEPOLIA-USDC-PLAN.md](BRIDGE-SEPOLIA-USDC-PLAN.md).

## The addresses and ids (Sepolia chain id 11155111 · testnet-1 `hashkinetics-1-4e4ea68d`)

| What | Where |
|---|---|
| USDC (Circle, Sepolia) | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` — get 20 per address per 2 h at [faucet.circle.com](https://faucet.circle.com) |
| HKVault (the lock/unlock vault) | `0x989Cb35485d16c7b19Dff890b617984EeD9970aF` — `bridge/contracts/src/HKVault.sol`, deployed 2026-09-09 (block ≈ 11,666,5xx) |
| HKWrapped `wHKT.sep` (reverse leg, ERC-20) | `0x24159bE1577f3016AD64beA7D1430e5F2313DB26` — `bridge/contracts/src/HKWrapped.sol` |
| Attestor (signs unlocks and wrapped mints) | `0x1d1d8e13792b318cdd593eb778fbb173bb3447d1` · threshold 1 |
| `USDC.sep` on testnet-1 | asset id `0c3c3f40884ef40aee41d2ae2b823c8cc1e2c0859172ef20ff899f015442c0f1` · 6 decimals · policy `mfps` (mintable, freezable, pausable, pool-eligible) · issuer `c58cf9224f21130eb2e0b67b2d64be1168f20e4dcdace75435e171f89be77a73` · registered at height 170,698 |
| `HKT` on testnet-1 (the asset the reverse leg wraps) | asset id `f2b88facb835a9e331b51772cf98cbcb95d6c86233324d252fd4c9edd8fbbcea` · 6 decimals · `mfps` · same issuer |
| Limits | unlocks capped at 1,000 USDC per day (vault `dailyCap`); smallest lock 0.01 USDC (`minLock`); mints on HK are not capped by the chain |
| Finality used | Sepolia `finalized` (two epochs, ≈ 12.8 min); a HashKinetics commit is final at once (BFT, ~1.35 s blocks) |

Check the asset from any machine: `curl -s -X POST https://rpc.hashkinetics.org -d '{"method":"hk_getAsset","params":{"asset":"0c3c3f40884ef40aee41d2ae2b823c8cc1e2c0859172ef20ff899f015442c0f1"}}'` — `supply − burned` must equal the vault's USDC balance (`balanceOf(0x989Cb354…)` on Sepolia); the service checks that every 10 minutes and refuses to act while it is off.

## Sepolia → testnet-1 (lock there, mint here)

You need: a HashKinetics account that **exists on chain** (the [faucet](https://www.hashkinetics.org/faucet) creates one from your auth commit — a mint to an id that does not exist yet is held by the bridge until it does), Sepolia ETH for gas, and USDC on Sepolia. With Foundry's `cast` (MetaMask + Etherscan's "write contract" works the same way):

```bash
R=https://ethereum-sepolia-rpc.publicnode.com; USDC=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238; VAULT=0x989Cb35485d16c7b19Dff890b617984EeD9970aF
HKACC=0x<your 64-hex account id>                     # hk-node account-info ~/my-account
cast send $USDC "approve(address,uint256)" $VAULT 20000000 --rpc-url $R --account <your keystore>      # 20 USDC (6 decimals)
cast send $VAULT "lock(uint256,bytes32)" 20000000 $HKACC --rpc-url $R --account <your keystore>
```

The `Locked` event carries a `depositId` (`keccak256(chainid, vault, nonce)`); the bridge mints exactly once per deposit id, whatever restarts happen in between. About 13 minutes later:

```bash
hk-node account-balance https://rpc.hashkinetics.org ~/my-account      # USDC.sep 20.000000
```

## testnet-1 → Sepolia (burn here, unlock there)

The destination is your Sepolia address as **exactly 20 bytes of hex, no `0x`** (a burn with any other destination length is valid on HashKinetics but *unbridgeable* — the bridge records it and never attests it; a refund is an issuer decision, never automatic). Your account pays the 100-micro protocol fee in the test asset, so keep a little of that.

```bash
hk-node asset burn ~/my-account https://rpc.hashkinetics.org 0c3c3f40884ef40aee41d2ae2b823c8cc1e2c0859172ef20ff899f015442c0f1 5000000 <40 hex chars of your Sepolia address>
cast call 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 "balanceOf(address)(uint256)" 0x<your Sepolia address> --rpc-url https://ethereum-sepolia-rpc.publicnode.com   # +5 USDC within ~2 min
```

The burn's txid is the `burnId`; the vault keeps `processed[burnId]`, so a burn is paid at most once. If the vault is paused (any attestor can pause; only the owner unpauses) or the day's cap is used up, the burn waits in the queue and is paid when the vault reopens — it is never lost.

## The reverse leg (`HKT` → `wHKT.sep` → `HKT`)

The same machinery wraps an HK-issued asset as an ERC-20 on Sepolia: burn `HKT` on testnet-1 naming a Sepolia address → the bridge mints `wHKT.sep` there (no finality wait: a HashKinetics commit is final); `HKWrapped.burn(amount, hkAccount)` on Sepolia → after Ethereum finality the issuer mints `HKT` back to that account. `HKT` is a test asset the bridge issuer mints as a float; wrapping the real HKN after TGE is a policy decision for counsel, not a build question.

```bash
hk-node asset burn ~/my-account https://rpc.hashkinetics.org f2b88facb835a9e331b51772cf98cbcb95d6c86233324d252fd4c9edd8fbbcea 4000000 <40 hex chars of your Sepolia address>
cast call 0x24159bE1577f3016AD64beA7D1430e5F2313DB26 "balanceOf(address)(uint256)" 0x<your Sepolia address> --rpc-url https://ethereum-sepolia-rpc.publicnode.com   # 4000000 within ~2 min
cast send 0x24159bE1577f3016AD64beA7D1430e5F2313DB26 "burn(uint256,bytes32)" 1000000 0x<your 64-hex account id> --rpc-url https://ethereum-sepolia-rpc.publicnode.com --account <your keystore>   # ~13 min later: +1 HKT on the account
```

**Receipts (2026-09-09, UTC):** float — the issuer minted 10 HKT to `cf1d6719…` (txid `25e8af8618d00a29d44fdbb2f1edf093f572b35ca95365bb8a4f46417cd326fa`, height 194,176) · burn 4 HKT naming `7a0543ee…` (txid `34e1a6af1a477e2f0380ef44417f69643d52247321485b38ebd72d3c49a2a5cd`, height 194,328) → `HKWrapped.mint` 4 wHKT.sep tx [`0x725ed38d…45af6`](https://sepolia.etherscan.io/tx/0x725ed38d361eef393f7193aa99631b9ee992b8ae4ba053ea575ad04f91d45af6), block 11,667,365, about a minute later · `HKWrapped.burn` 1 wHKT.sep naming `cf1d6719…` tx [`0x0cb4ac11…4fdd`](https://sepolia.etherscan.io/tx/0x0cb4ac118eda828fc1c71a7d8b7446ddf364625c3ac076402d4ecd84359f4fdd), block 11,667,380, 10:30:24, burnId `0x83ee199193df66e588ec12273ffbe45345c41f6c5c960fc434443164aa8c4201` → Sepolia finalized it at ≈ 10:47 → the issuer minted 1 HKT back to `cf1d6719…` (txid `54d57650533d7aa8ddb4f5e88c08d54c2e9a5b2acf095829a132c77c6220f79e`, height 195,196). After: the account holds 7 HKT (10 − 4 + 1), `HKT` supply 11 / burned 4, `wHKT.sep` total supply 3,000,000 = HKT burned − HKT re-minted.

## What can go wrong, and what happens then

| Case | Behaviour |
|---|---|
| Recipient account does not exist on HK | mint held (`held_recipient`), retried until it exists; visible on the service's `/health` |
| Sepolia reorg before finality | never eligible — nothing minted |
| Asset paused / recipient frozen on HK | mint held with the chain's receipt string; the issuer resolves it |
| Vault paused / daily cap reached | burn queued (`queued_paused` / `queued_cap`), drained when reopened |
| Service crash between "submitted" and "recorded" | that item is **held for review** and never auto-retried — an operator checks the chain and resolves it with `attest-ledger` (the devnet gate proves this with a `kill -9` mid-flow) |
| Destination not 20 bytes | `unbridgeable`, never attested |

## Receipts (the first real loop, 2026-09-09, UTC)

| Step | Where | Receipt |
|---|---|---|
| Lock 20 USDC naming account `cf1d6719f733485d9907f7a487770930e7dd3444b02c74fcb3e342ff16e9ea00` | Sepolia | tx [`0x0a8d4b58…30b09`](https://sepolia.etherscan.io/tx/0x0a8d4b58165a7d3dd25c552470d6eeb0b6d8ba86b6e417b3264e5461c2930b09) · block 11,666,663 · 08:02:12 · depositId `0x5e8ed19f48a897fe2723964a557fc1123e00c3c52ef4f69ab9ced6f342de68b2` |
| Sepolia finalizes the block | Sepolia | `finalized` reached 11,666,687 at ≈ 08:21 (19 min — all of it Ethereum finality; the service polls every 5 s) |
| Mint 20 USDC.sep to that account | testnet-1 | txid `2d8a80e5e7c5227fe0ad943a0d2a16ecc67205c3e9ce8127bb4b37d4ac3ccfb0` · height 188,826 · sender = the issuer `c58cf922…` · receipt `ok: 1 event(s)` |
| Burn 5 USDC.sep, destination `7a0543ee2dcdac2e351b95bcad57117f7acf9eda` | testnet-1 | txid `9051289e40acb2b3566067d711eb3c9da2beac28aab19bb82e8fbd70baed981c` · height 190,324 · ≈ 08:53 |
| Unlock 5 USDC to that address | Sepolia | tx [`0xfdd45642…e046`](https://sepolia.etherscan.io/tx/0xfdd45642656280a4010ee929165b7a129b0e41add3a7a012c13030bcee14e046) · block 11,666,916 · 08:54:36 · from the attestor · burnId = the burn txid · 153,395 gas |
| Reconciliation after the loop | both | vault `balanceOf` 15,000,000 = `supply` 20,000,000 − `burned` 5,000,000 · the account holds 15 USDC.sep · the Sepolia address holds its 5 USDC |

Check any line yourself: `hk_getTx {"txid": …}` on `https://rpc.hashkinetics.org`, `hk_getAsset` for supply/burned, Etherscan for the Sepolia side.

## Run it yourself

Contracts: `bridge/contracts` (Foundry; `forge test` → 28 tests). Service: `hk-node attest-serve CONFIG.toml` (`chain/crates/hk-node/src/attest.rs` + `eth.rs`), config `ops/attest.toml.example`, unit `ops/hk-attest.service`. The end-to-end receipt on a local devnet + `anvil`: `chain/gate-b1.sh` (11 sections, 50 checks). A second attestor joins with `hk-node attest-cosign` — it re-checks every burn on its own node before signing.
