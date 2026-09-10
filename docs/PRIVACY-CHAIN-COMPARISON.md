# Privacy chains vs HashKinetics — the in-depth chart (draft for review, 2026-09-10)

**How to read this.** One row per property, one column per chain. Every HashKinetics cell says *measured*, *live*, or *plan*; nothing in the HK column is claimed that has not run on testnet-1 or a gated devnet, and the last rows say plainly what the others have that we do not (years of mainnet, audits, liquidity). The competitor cells are taken from each project's public documentation as of September 2026; they are stated neutrally and a wrong cell is a bug — please correct it before this goes on the site. Rule for the site version: no adjective we cannot measure, no price, nothing for sale.

The ten chains Yadu listed fall into four families, and the families matter more than the names:

| Family | Chains | Privacy comes from | The thing to know |
|---|---|---|---|
| **Ring-signature / CryptoNote** | Monero, Beldex | Ring signatures + stealth addresses + RingCT (hidden amounts) | Mandatory privacy, decoy-based anonymity sets (Monero: 16); Monero's FCMP++ upgrade replaces rings with curve-tree membership proofs |
| **zk-SNARK shielded pools** | Zcash, Pirate Chain, (Horizen, formerly) | Note commitments + nullifiers + zero-knowledge proofs | Zcash Sapling needed a trusted setup, Orchard (Halo 2) does not; Pirate is shielded-only on Sapling; Horizen retired its shielded pool in 2023 |
| **One-out-of-many / mixing** | Firo (Lelantus Spark), Dash (CoinJoin), Decred (StakeShuffle) | Firo: cryptographic hiding of sender, amount, recipient, no trusted setup · Dash/Decred: coin mixing, amounts visible | Mixing raises the cost of tracing; it does not hide amounts or make a proof about them |
| **Trusted-hardware smart contracts** | Secret Network, Oasis (Sapphire) | Encrypted contract state inside Intel SGX enclaves | Privacy is as strong as the enclave; programmable, with viewing keys/permits |
| **HashKinetics** | — | Hash-committed notes + STARK spend proofs + ML-KEM-768 stealth addresses, one pool per asset; hash-based signatures for every spend and every validator vote | The only column where the money path contains no elliptic curve at all; also the only testnet-only column |

## The chart

Legend: ● yes · ○ no · ◐ partial / optional · **T** testnet-only claim (HK) · *m* measured · *p* plan. "PQ" = safe against a cryptographically relevant quantum computer as far as the primitive is concerned (hash functions / lattice KEM vs elliptic-curve discrete log).

| Property | **HashKinetics** | Monero (XMR) | Zcash (ZEC) | Firo (FIRO) | Pirate Chain (ARRR) | Dash (DASH) | Decred (DCR) | Secret (SCRT) | Oasis (ROSE) | Horizen (ZEN) | Beldex (BDX) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Mainnet since | **none — testnet-1 since 2026-09-02, pre-audit** (T) | 2014 | 2016 | 2016 (as Zcoin) | 2018 | 2014 | 2016 | 2020 | 2020 | 2017 | 2019 |
| Privacy by default | ● shielded pool is the payment path; transparent accounts exist for fees, issuance and bridges (live, T) | ● mandatory | ◐ optional (t-/z-addresses) | ◐ optional (transparent + Spark) | ● shielded-only | ◐ optional CoinJoin | ◐ optional mixing | ◐ per contract (SNIP-20 tokens private) | ◐ per contract (Sapphire ParaTime) | ○ shielded pool retired (2023); privacy via ZK app chains | ● mandatory |
| Hidden: amount | ● (m) | ● RingCT | ● in shielded | ● Spark | ● | ○ | ○ | ● in contract state | ● in contract state | ○ | ● |
| Hidden: sender | ● (m) | ◐ 16-member ring (FCMP++ → whole chain, in rollout) | ● | ● one-out-of-many | ● | ◐ mixed | ◐ mixed | ● | ● | ○ | ◐ ring |
| Hidden: recipient | ● stealth (ML-KEM-768) (m) | ● stealth | ● | ● Spark address | ● | ○ | ○ | ● | ● | ○ | ● stealth |
| Hidden: memo | ● inside the note ciphertext (m) | n/a (no memo field; tx_extra public) | ● encrypted memo | ● | ● | ○ | ○ | ● | ● | ○ | n/a |
| Privacy primitive | note commitments + nullifiers + **STARK** (hash-based, SHA-256 in-circuit) | ring signatures (CLSAG) + Bulletproofs+ | zk-SNARK: Sapling (Groth16), Orchard (Halo 2) | Lelantus Spark (one-out-of-many, Bulletproofs-style range proofs) | zk-SNARK (Sapling) | CoinJoin | CoinShuffle++ | TEE (Intel SGX) | TEE (Intel SGX) | (zk-SNARK Sapling, retired) | ring signatures (CryptoNote) |
| Trusted setup | ○ none (m) | ○ none | ◐ Sapling yes (2018 MPC), Orchard none | ○ none | ● Sapling ceremony inherited | ○ none | ○ none | ○ (hardware trust instead) | ○ (hardware trust instead) | ● (Sapling) | ○ none |
| **PQ: spend signatures** (can a quantum computer steal funds?) | ● **hash-based only** — SLH-DSA roots, LMS/HSS operational keys, WOTS spends; no ECDSA/EdDSA anywhere money moves (live, T) | ○ Ed25519 | ○ RedPallas/RedJubjub, secp256k1 | ○ secp256k1 + Spark curve keys | ○ | ○ secp256k1 | ○ secp256k1 | ○ Ed25519/secp256k1 | ○ Ed25519/secp256k1 | ○ | ○ Ed25519 |
| **PQ: validator / consensus keys** | ● hash-based votes and proposals; keys rotate by root-signed certificate (live, T) | ○ PoW (no keys) — n/a | ○ PoW; Crosslink PoS in development | ○ masternode BLS/ECDSA | ○ dPoW notaries ECDSA | ○ masternode BLS | ○ PoS tickets ECDSA | ○ Tendermint Ed25519 | ○ Ed25519 | ○ | ○ PoS Ed25519 |
| **PQ: the privacy layer** (can a quantum computer de-anonymise history?) | ● STARK soundness is hash-based; stealth addresses are ML-KEM-768 (FIPS 203). Honest matrix: an ML-KEM break could leak old *metadata*, never money (live, T) | ○ ring anonymity rests on ECDLP — retroactively breakable | ○ SNARK soundness and note encryption rest on ECC — forgeable / decryptable retroactively | ○ ECC | ○ ECC | ○ (mixing only) | ○ | ○ enclave keys ECC | ○ | ○ | ○ |
| Consensus | hash-based BFT (Malachite/Tendermint-style), ~1.35 s blocks live, 1.0 s floor (m) | PoW RandomX, 2 min | PoW Equihash, 75 s (hybrid PoS planned) | PoW FiroPoW + masternode ChainLocks, ~5 min | PoW + Komodo dPoW notarisation, 60 s | PoW X11 + masternode ChainLocks, 2.5 min | hybrid PoW/PoS (PoS-dominant since 2023), 5 min | Tendermint PoS, ~6 s | Tendermint-style PoS, ~6 s | PoW, 2.5 min | PoS with masternodes, ~30 s |
| Finality | one commit (BFT) | probabilistic | probabilistic | ChainLocks (fast) | notarised | ChainLocks | probabilistic + ticket votes | one commit | one commit | probabilistic | ~ |
| Selective disclosure to an auditor / court | ● **one-time disclosure package** opens exactly one payment, verifies offline (m: 0 of the other 21 opened) · **epoch viewing keys**: one wallet, chosen epochs, incoming only (live) | ◐ view key (incoming only, all history); tx key per payment | ● incoming/full viewing keys; payment disclosure | ● incoming view keys (Spark), per-payment proof | ◐ viewing keys (Sapling) | ○ (transparent anyway) | ○ | ● viewing keys + query permits (per contract) | ◐ contract-defined | ○ | ◐ view key |
| A master / global view key | ○ **structurally none** — the commitment scheme has no slot for one (decision D8) | ○ | ○ | ○ | ○ | n/a | n/a | ○ (enclave operators are the trust) | ○ (enclave) | ○ | ○ |
| Regulated-asset controls (freeze one account, pause an asset) | ● for issued assets, fixed at registration (live, T — bridged USDC.sep carries both) | ○ | ○ (ZSAs planned) | ○ | ○ | ○ | ○ | ◐ per token contract | ◐ per contract | ○ | ○ |
| Travel-rule / ramp envelopes required by consensus | *p* (P3.3) | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| **Spending budgets enforced by consensus over hidden balances** (MandateTree) | ● **unique** — an over-budget agent is refused by the state machine, not by an app (m: `rejected: mandate: insufficient buffer at depth 1`) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ programmable in a contract (trusts the enclave) | ◐ same | ○ | ○ |
| Multiple assets in shielded form | ● one pool per pool-eligible asset since height 190,000 (live, T: bridged USDC.sep shielded 2026-09-09) | ○ | *p* ZSAs (ZIP 226/227) | ○ | ○ | ○ | ● private SNIP-20 tokens | ● | ○ | ○ |
| Stablecoin / bridge to Ethereum | ● Sepolia USDC ↔ testnet-1, both directions, public receipts; **1-of-1 attestor today** (T) | ○ (third-party swaps) | ◐ third-party bridges | ○ | ○ | ○ | ○ | ● IBC + bridges | ● bridges | ● (Base L3 pivot) | ○ |
| General smart contracts | ○ — MandateTree, channels, issued assets only (deliberate) | ○ | ○ | ○ | ○ | ◐ Platform | ○ | ● CosmWasm (private) | ● EVM (private) | ● EVM sidechain | ○ |
| Proof cost per shielded spend | ~1.3 s on a consumer GPU (m); verify ~100 ms per seat | signing ms-scale; verification per input | ~1–2 s (Orchard, CPU) | ~1 s | Sapling-class | n/a | n/a | enclave | enclave | — | ms-scale |
| Per-block verification of shielded spends | ● **one constant-size ~1.24 MB aggregate STARK**, 256 spends folded in 75 s on one RTX 5090 (m) | per-tx | per-tx | per-tx | per-tx | n/a | n/a | n/a | n/a | — | per-tx |
| Throughput (as stated by us / them) | 274 tx/s sustained, 4-validator **devnet**, storm harness (m; the public-testnet run is pending) | ~ | ~ | ~ | ~ | ~ | ~ | ~ thousands (Tendermint-class) | ~ | ~ | ~ |
| Node cost | 4 cores / 4–8 GB, no GPU (validators verify) (m) | modest | modest | modest | modest | masternode collateral | ticket price | validator stake | validator stake | node/secure node | masternode collateral |
| Independent audits | **none yet** — CertiK engaged, scope frozen at tag `audit-2026-09`, mainnet gated behind them | many, over a decade | many (NCC, Least Authority, QED-it…) | several (Lelantus/Spark audited) | inherits Sapling audits | several | several | several | several | several | ~ |
| Governance today | founders decide alone under bootstrap governance (16 of 20 power) — said on the site; handover by dated milestone | community/PoW | ZF/ECC/Shielded Labs, dev fund | community + masternodes | community | masternode votes | on-chain Politeia | on-chain | on-chain | Horizen DAO | masternode votes |
| Open source | ● MIT/Apache since 2026-08-26 | ● | ● | ● | ● | ● | ● | ● | ● | ● | ● |
| Liquidity / listings | none — nothing is for sale | wide (delisted in several jurisdictions) | wide | moderate | limited | wide | moderate | moderate | wide | moderate | limited |

## What the chart says, in five lines

1. **Post-quantum is the whole column, not a feature.** Every other chain in the list signs spends, and (where it has them) validator votes, with elliptic-curve keys, and every one of their privacy layers rests on the elliptic-curve discrete-log problem — ring signatures, Groth16/Halo 2 SNARKs, Spark's one-out-of-many proofs, and the enclaves' key exchange alike. A cryptographically relevant quantum computer can steal from them *and* de-anonymise their histories retroactively. HashKinetics' money path — spend signatures, validator votes, the proof system, the stealth addressing — contains no elliptic curve at all. Its honest exposure is that an ML-KEM break could leak old metadata; never money.
2. **Privacy strength is comparable to the best of them, by a different route.** Amount, sender, recipient and memo are hidden as in Zcash-shielded, Firo Spark and Monero; the anonymity set is the whole pool (like Zcash/Firo, unlike Monero's 16-member rings until FCMP++); there is no trusted setup (like Orchard, Firo, Monero; unlike Sapling/Pirate); and the block's spends verify as one aggregate proof, which none of them do.
3. **Lawful access is the row nobody else fills the same way.** Viewing keys exist on Zcash, Firo, Monero and Secret. What exists only here: a one-time disclosure package that opens exactly one payment and verifies offline, epoch-scoped viewing keys, issuer freeze/pause on regulated assets, and — as a stated constitutional decision — no slot for a master key. The travel-rule and bonded-completeness rows are plans and say so.
4. **Budgets enforced by consensus over hidden balances exist nowhere else in production.** The nearest analogue is a spending policy inside a Secret or Oasis contract, which trusts an SGX enclave.
5. **They have what we do not:** years of mainnet, audits, liquidity, wallets in the wild. HashKinetics is a testnet with 8 seats, a bridge with one attestor key, and an audit that has not happened. The site must say this in the same table, not in a footnote.

## Proposed front-page version (condensed — 7 rows, 6 columns; the full chart links from it)

Columns: **HashKinetics** · Monero · Zcash · Firo · Secret / Oasis (TEE) · Dash / Decred (mixing). Pirate Chain, Beldex and Horizen fold into the Zcash / Monero / "retired" notes in the full chart.

| | HashKinetics | Monero | Zcash | Firo | Secret / Oasis | Dash / Decred |
|---|---|---|---|---|---|---|
| Privacy | shielded pool is the payment path | mandatory | optional | optional | per contract (SGX) | optional mixing, amounts visible |
| Hidden: amount · sender · recipient | ● ● ● | ● ◐(ring) ● | ● ● ● (shielded) | ● ● ● | ● ● ● (in the enclave) | ○ ◐ ○ |
| Quantum-safe money path (spends, votes, proofs) | **● hash-based only** | ○ | ○ | ○ | ○ | ○ |
| Trusted setup | none | none | Sapling yes / Orchard none | none | hardware trust | none |
| Lawful access without a master key | one-time offline-verifiable disclosure · epoch viewing keys · issuer freeze/pause | view key | viewing keys | view keys | viewing keys / permits | n/a |
| Budgets enforced by consensus over hidden balances | **● unique** | ○ | ○ | ○ | ◐ in a contract | ○ |
| Status | **testnet-1, 8 seats, pre-audit, nothing for sale** | mainnet since 2014 | mainnet since 2016 | mainnet since 2016 | mainnet since 2020 | mainnet since 2014 / 2016 |

Caption for the site: *"Every cell about another chain comes from its public documentation as of September 2026 and is neutral by intent — tell us what we got wrong. Every cell about us is measured on a testnet or labelled a plan. The full chart, with sources: docs/PRIVACY-CHAIN-COMPARISON.md."*

## Sources to cite on the site (project documentation, checked September 2026)

Monero: getmonero.org (RingCT, CLSAG, Bulletproofs+, FCMP++ research) · Zcash: z.cash and zips.z.cash (Sapling MPC, Orchard/Halo 2, viewing keys, ZIP 226/227 ZSAs, Crosslink) · Firo: firo.org (Lelantus Spark whitepaper and audits) · Pirate Chain: piratechain.com (shielded-only, dPoW) · Dash: docs.dash.org (CoinJoin, ChainLocks, Platform) · Decred: docs.decred.org (StakeShuffle, DCP-0012) · Secret Network: docs.scrt.network (SGX, viewing keys, permits, SNIP-20) · Oasis: docs.oasis.io (Sapphire, TEE model) · Horizen: horizen.io (ZEN 5.0 shielded-pool deprecation, Horizen 2.0) · Beldex: beldex.io · HashKinetics: hashkinetics.org/receipts, /facts.json, docs/SHIELDED-POOL-SPEC.md, docs/LAWFUL-ACCESS.md, docs/CAPACITY-SHEET.md, docs/BRIDGE-GUIDE.md.

## Review notes for Yadu (cells I want a second pair of eyes on before publishing)

- Monero FCMP++: in final development/rollout as of mid-2026 — if it has activated by the time this ships, the sender cell becomes ● and the note changes.
- Firo's block time and Beldex's consensus details are marked ~; confirm from their docs.
- Horizen: the mainchain shielded pool was deprecated in 2023 and the project pivoted to a ZK app-chain / Base L3 — if you'd rather not list a chain that no longer competes on coin privacy, drop the column.
- Throughput for other chains is deliberately "~": we do not publish numbers we did not measure ourselves; ours is labelled devnet.
- The audit and liquidity rows are the honesty rows; they stay in the site version.
