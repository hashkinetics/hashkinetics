# HashKinetics JSON-RPC — the complete reference (node v0.17.0)

**Every method the node answers, with parameters, result shapes, limits and the errors you can get.** The public endpoint is `https://rpc.hashkinetics.org` (testnet-1, `hashkinetics-1-4e4ea68d`); a local node answers on `http://127.0.0.1:26000`. This is the same API the website, the explorer, the faucet and the Windows wallet use — there is no second, private one. Source of truth: `chain/crates/hk-node/src/rpc.rs` (one `dispatch` match; if this page and the code disagree, the code wins and this page has a bug).

## Transport

- HTTP/1.1 **POST**, any path, body `{"method": "<name>", "params": {…}}`. The `jsonrpc`/`id` fields of JSON-RPC 2.0 are accepted and ignored; `params` may be omitted for methods that take none.
- Responses are `{"result": …}` or `{"error": "<message>"}` (HTTP 200 for both; HTTP 400 for unparseable JSON; HTTP 413-equivalent refusal above 8 MiB of body).
- **No authentication, no rate limit, CORS `*`.** Operators: keep your own node's RPC on loopback or firewalled to peers (`docs/VALIDATOR-ONBOARDING.md` §0/§4); the public endpoint sits behind a reverse proxy and Cloudflare.
- All amounts are **micro-units as decimal strings** (u128); `1.000000` = `"1000000"`. Ids, hashes and hex fields are lowercase hex without `0x`. Asset ids are 32-byte hex; the transparent test unit is `0909…09` (32 × `09`).

```bash
curl -s -X POST https://rpc.hashkinetics.org \
  -d '{"method":"hk_chainInfo","params":{}}'
```

## Chain & liveness

| Method | Params | Result |
|---|---|---|
| `hk_chainInfo` | — | `chain_id`, `genesis_digest`, `node_version` (v0.15.2: the binary answering, e.g. `v0.15.2`), `peers` (v0.15.2: live p2p peer count), `height`, `app_hash`, `signer{epoch, remaining, capacity}` (this node's own operational-key budget; observers report their own unused tree), `fee{micro, from_height, burned_micro}`, `history{disk_from, ram_window, indexed_txs, retain_blocks}` (v0.16.0: `retain_blocks` = null on an archive node, N when the node prunes segments older than tip−N), `process{rss_bytes, uptime_secs, verifier_init_ms}` (v0.17.0 / R11: this process's resident set in bytes — Linux only, null elsewhere — seconds since `start`, and how long the verify-only STARK client took to come up; null when no verifier is wired. The onboarding doc's RAM line is checkable with this call.) |
| `hk_getValidators` | — | `count`, `total_power`, `validators[{address, voting_power, epoch, root_pk}]` — the set as of the tip; `epoch` climbs on every self-rotation |
| `hk_getMempool` | — | `count`, `txids[≤100]` — this node's pending admissions |
| `hk_getPeers` | — | **v0.15.2 (N1).** This node's live p2p peer table, straight from its swarm: `self{peer_id, version, genesis_digest}`, `count`, `inbound`, `outbound`, `public_addr` (peers on a public address), `identified` (identify received on the consensus protocol), `islands_refused` (peers on a different genesis disconnected by the genesis gate since boot), `peers[{peer_id, direction: inbound\|outbound, addr, private_addr, version, genesis: match\|untagged\|pending\|mismatch, identified, connected_secs, connections}]`. `addr` is the connection's real remote address masked by the node to its /24 (v4) or /48 (v6) — never what the peer claims to listen on; `private_addr` marks loopback / RFC 1918 / CGNAT / ULA peers (the founding fleet peers over its private network); `version` is `null` for a ≤ v0.15.1 peer (it advertises its genesis but not its version). An entry exists only while a connection is open. The gateway's table is the network's public roll call because every kit node bootstraps through it; a node that peers only with other operators is not visible there |

`fee.burned_micro` is the cumulative burn since genesis (in `C(Σ)` once nonzero); `history.disk_from` is the lowest height this node can serve from its block log (the gap-free suffix — R10 v2), `ram_window` the number of recent decided heights held in memory, `indexed_txs` the size of the node-local search index (since v0.16.0 it is restored from `index3.bin` on restart, so it is rarely 0), `retain_blocks` (v0.16.0) the node's `HK_RETAIN_BLOCKS` setting or null — a pruned node answers `hk_getBlock` below `disk_from` with `not found`; point explorers and auditors at an archive node such as the public endpoint.

## Blocks & history

| Method | Params | Result |
|---|---|---|
| `hk_getBlocks` | `before?` (height, exclusive), `limit?` (default 20, **max 50**) | `blocks[{height, time, tx_count, aggregate, rotations, value_id}]` newest-first, `earliest` (= `history.disk_from`), `latest` |
| `hk_getBlock` | `height` | `found`, `height`, `time`, `parent_app_hash`, `tx_count`, `txs[{txid, sender, nonce, kind, fields{…}, receipt}]`, `aggregate` (bool — one STARK covered the block's spends), `rotations` (count of rotation certificates applied at this height), `certificate{round, value_id, signatures}` |
| `hk_getTx` | `txid` | `found`, `txid`, `height`, `index`, `summary{txid, sender, nonce, kind, fields}`, `receipt` — via the node-local tx index; `found:false` until the index pass has reached that height after a restart |
| `hk_getAccountTxs` | `id`, `limit?` (default 25, **max 100**) | `id`, `total`, `txs[{txid, height, kind}]` newest-first — every envelope the account sent or was credited by |
| `hk_getReceipt` | `txid` | `found`, `detail` — the consensus receipt string (`ok: <n> event(s)` or `rejected: <rule>`), from a ring of the newest 4,096 receipts; older receipts come back through `hk_getTx.receipt` |

`kind` is one of `transfer`, `account_create`, `mandate_create`, `mandate_spend`, `mandate_revoke`, `channel_open`, `channel_settle`, `channel_refund`, `shield`, `shielded_spend`, and since v0.15.0 (X1) `asset_register`, `asset_mint`, `asset_burn`, `asset_freeze`, `asset_pause` (fields: asset, symbol/decimals/policy, to/amount, destination hex, account/frozen, paused). Refusal receipts an issuer policy produces read `rejected: asset paused`, `rejected: frozen by issuer`, `rejected: asset is not pool-eligible`, `rejected: sender is not the asset's issuer`, `rejected: asset policy forbids this (…)`. Transparent kinds expose sender, counterparty and amount in `fields` (this is the transparent skeleton by design); pool kinds expose only nullifier / commitments / the pool fee. `hk_getBlock`/`hk_getBlocks` answer `{"error":"persistence disabled on this node (HK_NO_PERSIST)"}` on a node started without a block log.

## Accounts & money

| Method | Params | Result |
|---|---|---|
| `hk_getAccount` | `id` | `found`, `nonce` (= the next ratchet index), `auth_commit` (the currently committed one-time key), `balances[{asset, symbol?, amount, frozen}]` (X1, v0.15.0: every non-zero transparent balance, by asset) |
| `hk_balance` | `id`, `asset` | `amount` (string, micro) |
| `hk_getAsset` | `asset` **or** `issuer` + `symbol` | X1 (v0.15.0): `found`, `asset{asset, symbol, decimals, issuer, policy{flags, mintable, freezable, pausable, pool_eligible}, supply, burned, circulating, held, conserved, paused, frozen_count, registered_at}` — `conserved` is the node's own I5' check (`held == circulating`); `asset_id` echoes the derived id when not found |
| `hk_getAssets` | — | X1: `count`, `fee_asset`, `assets[…]` (the whole registry, same shape) |
| `hk_submitTx` | `tx` (a `SignedTx` JSON object — the CLI and the wallet build these) | `accepted: true, txid` or `accepted: false, reason` (mempool admission mirrors the state machine's checks: nonce window, balance **including the 100-micro envelope fee**, duplicate nullifier, …); an accepted tx is also pushed to the node's gossip peers |
| `hk_mandateAvailable` | `leaf` (mandate id), `at?` (unix seconds; default chain time) | `available` (string, micro) — what the leaf may spend right now under every ancestor's drip and cap, or `null` + `reason` |
| `hk_getChannel` | `id` | `payer`, `payee`, `asset`, `mandate`, `tip`, `unit_price`, `max_steps`, `highest_step_settled`, `escrow_remaining`, `expiry`, `refunded` — a PayWord channel's full state |

Every envelope pays the protocol fee (`docs/FEES.md`): a transfer of `amount` needs `amount + fee.micro` available; the receipt for a shortfall is `rejected: insufficient balance for the protocol fee (have <a>, need <b>)` (fee) or `rejected: insufficient balance: have <a>, need <b>` (payload after the fee was debited).

## Shielded pool

| Method | Params | Result |
|---|---|---|
| `hk_getPoolInfo` | — | `version`, `asset`, `root` (current commitment-tree root), `latest_anchor`, `next_index`, `nullifiers` (count), `total_shielded` (string, micro — the pool's conservation ledger) |
| `hk_getPoolNotes` | `from?` (leaf index, default 0), `limit?` (default and cap 10,000) | `notes[{index, commitment, stealth_ct}]`, `from`, `count`, `total`, `next` — **paged since v0.16.1 (H3)**: `next` is the index the following page starts at, `null` when this page reached the end. A wallet keeps `next` as its scan cursor and asks only for what it has not trial-decrypted yet (the pool is append-only); a page of 10,000 notes is ≈24 MB of hex, so clients on slow links page smaller (the desktop wallet uses 2,000) |
| `hk_getPoolLeaves` | `from?`, `limit?` (same paging) | `leaves[hex…]`, `from`, `count`, `total`, `next` — the commitment list, for a client that insists on rebuilding paths itself |
| `hk_getPoolPath` | `index` | `index`, `commitment`, `siblings[32]` (bottom → top), `root`, `total` — **v0.16.1 (H3)**: one authentication path, so a spender never downloads the pool. The wallet re-folds the siblings and refuses a path that does not reach `root`; the proof binds that root, which the chain accepts only while it is a recent anchor — a wrong path from a node can cost the spender a rejected transaction, never a coin. `index` out of range → `error` |
| `hk_nullifierSpent` | `nullifier` | `spent` (bool) |
| `hk_submitBundle` | `txs[]` (proof-less pool txs), `agg_proof` (hex, one aggregate STARK) | `accepted`, `txids[]` — the aggregator path (P2.3): one proof for every spend in the bundle |

## Operator

| Method | Params | Result |
|---|---|---|
| `hk_submitRotation` | `cert` (a root-signed `RotationCert`) | `accepted`, `epoch`, `queued` — queues a **foreign** validator's rotation certificate for this node's next proposal (the peer-carried revival path: `hk-node issue-rotation <HOME> <EPOCH>` produces the cert offline; any live node carries it in) |
| `hk_submitSetChange` | `cert` (a `SetChangeCert`: body + approvals) | `accepted`, `queued`, `approvals`, `window` — **V1 (v0.14):** queues a validator-set change (admit / remove one seat) approved by root signatures from strictly more than ⅔ of the current seats' voting power; re-verified at propose and at commit; effective one height after it commits. `hk-node set-change propose|approve|assemble` builds it (docs/V1-VALIDATOR-SET-CHANGES.md) |
| `hk_gossipTxs` | `txs[]` | `admitted`, `dropped` — peer ingress for transaction gossip (single hop: gossiped txs are admitted, never re-forwarded). Meant for validator-to-validator use over a firewalled RPC |

## Errors you will actually see

`unknown method: <name>` · `missing/invalid param: <name>` · `persistence disabled on this node (HK_NO_PERSIST)` · `rejected: …` receipts inside `hk_submitTx` results (the tx was *admitted or refused by the mempool*; a tx that is admitted but later refused in a block gets its `rejected:` string via `hk_getReceipt` / `hk_getTx`).

Since v0.15.2 `hk_getBlock` also returns `set_changes[{change: admit|remove, root_pk, voting_power, approvals, not_before, not_after}]` and `hk_getBlocks` entries carry `set_changes` (count) — the validator-set change certificates a block carries (block 72219 on testnet-1 seated the first external validator).

## Examples against testnet-1 (2026-09-03; `hk_getPeers` after the v0.15.2 roll)

```bash
# the chain, its fee policy and its history window
curl -s -X POST https://rpc.hashkinetics.org -d '{"method":"hk_chainInfo"}'
# → {"result":{"chain_id":"hashkinetics-1-4e4ea68d","height":15897,…,"fee":{"micro":"100","from_height":1,"burned_micro":"900"},"history":{"disk_from":1,"ram_window":512,"indexed_txs":9}}}

# the block where the first testnet-1 rotation certificate landed
curl -s -X POST https://rpc.hashkinetics.org -d '{"method":"hk_getBlock","params":{"height":11584}}'
# → {"result":{"found":true,"height":11584,"rotations":1,"tx_count":0,"time":1788373803,"certificate":{…}}}

# one transfer, found through the search index
curl -s -X POST https://rpc.hashkinetics.org -d '{"method":"hk_getTx","params":{"txid":"7147b014e7469c429f19420c993c79cf75f3a076dc941107b06417ca0bb93087"}}'
# → {"result":{"found":true,"height":2199,"summary":{"kind":"transfer","fields":{"amount":"1000000000",…}},"receipt":"ok: 1 event(s)"}}

# who is on the network right now, as the gateway sees it (v0.15.2)
curl -s -X POST https://rpc.hashkinetics.org -d '{"method":"hk_getPeers"}'
# → {"result":{"self":{"peer_id":"12D3KooW…","version":"v0.15.2",…},"count":4,"inbound":1,"outbound":3,"public_addr":1,"identified":4,"islands_refused":0,
#      "peers":[{"peer_id":"12D3KooW…","direction":"inbound","addr":"/ip6/2a02:c207:2355::/tcp/27000","private_addr":false,"version":"v0.15.2","genesis":"match","identified":true,"connected_secs":3612,"connections":1}, …]}}
```

## Limits and refusals (v0.13.2)

Per request: 10 s to arrive in full (`408 request timed out`), 8 MiB body (`413`), 256 concurrent connections per node (`503 rpc busy`). **Operator methods are not browser-callable:** `hk_submitRotation`, `hk_submitSetChange`, `hk_gossipTxs` and `hk_submitBundle` answer `403` when the request carries an `Origin` header (a web page cannot drive a node's operator surface even when it can reach it); every other method, including `hk_submitTx`, keeps CORS `*`. `hk_submitBundle` queues at most 64 bundles and refuses a duplicate aggregate; `hk_gossipTxs` takes at most 1,024 txs per call. Still ledgered (`docs/P3.2-IMPLEMENTATION-PLAN.md`): no auth, no per-client rate limit · `hk_getPoolNotes`/`hk_getPoolLeaves` are paged (≤ 10,000 per call) and `hk_getPoolPath` answers one path since v0.16.1 (H3) · `hk_getAccountTxs` turns any account id into its full transparent payment graph (by design of the transparent skeleton; shield if you need privacy).
