# HashKinetics JSON-RPC — the complete reference (node v0.13.0)

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
| `hk_chainInfo` | — | `chain_id`, `genesis_digest`, `height`, `app_hash`, `signer{epoch, remaining, capacity}` (this node's own operational-key budget; observers report their own unused tree), `fee{micro, from_height, burned_micro}`, `history{disk_from, ram_window, indexed_txs}` |
| `hk_getValidators` | — | `count`, `total_power`, `validators[{address, voting_power, epoch, root_pk}]` — the set as of the tip; `epoch` climbs on every self-rotation |
| `hk_getMempool` | — | `count`, `txids[≤100]` — this node's pending admissions |

`fee.burned_micro` is the cumulative burn since genesis (in `C(Σ)` once nonzero); `history.disk_from` is the lowest height this node can serve from its block log (the gap-free suffix — R10 v2), `ram_window` the number of recent decided heights held in memory, `indexed_txs` the size of the node-local search index (0 while the background index pass is still running after a restart).

## Blocks & history

| Method | Params | Result |
|---|---|---|
| `hk_getBlocks` | `before?` (height, exclusive), `limit?` (default 20, **max 50**) | `blocks[{height, time, tx_count, aggregate, rotations, value_id}]` newest-first, `earliest` (= `history.disk_from`), `latest` |
| `hk_getBlock` | `height` | `found`, `height`, `time`, `parent_app_hash`, `tx_count`, `txs[{txid, sender, nonce, kind, fields{…}, receipt}]`, `aggregate` (bool — one STARK covered the block's spends), `rotations` (count of rotation certificates applied at this height), `certificate{round, value_id, signatures}` |
| `hk_getTx` | `txid` | `found`, `txid`, `height`, `index`, `summary{txid, sender, nonce, kind, fields}`, `receipt` — via the node-local tx index; `found:false` until the index pass has reached that height after a restart |
| `hk_getAccountTxs` | `id`, `limit?` (default 25, **max 100**) | `id`, `total`, `txs[{txid, height, kind}]` newest-first — every envelope the account sent or was credited by |
| `hk_getReceipt` | `txid` | `found`, `detail` — the consensus receipt string (`ok: <n> event(s)` or `rejected: <rule>`), from a ring of the newest 4,096 receipts; older receipts come back through `hk_getTx.receipt` |

`kind` is one of `transfer`, `account_create`, `mandate_create`, `mandate_spend`, `mandate_revoke`, `channel_open`, `channel_settle`, `channel_refund`, `shield`, `shielded_spend`. Transparent kinds expose sender, counterparty and amount in `fields` (this is the transparent skeleton by design); pool kinds expose only nullifier / commitments / the pool fee. `hk_getBlock`/`hk_getBlocks` answer `{"error":"persistence disabled on this node (HK_NO_PERSIST)"}` on a node started without a block log.

## Accounts & money

| Method | Params | Result |
|---|---|---|
| `hk_getAccount` | `id` | `found`, `nonce` (= the next ratchet index), `auth_commit` (the currently committed one-time key) |
| `hk_balance` | `id`, `asset` | `amount` (string, micro) |
| `hk_submitTx` | `tx` (a `SignedTx` JSON object — the CLI and the wallet build these) | `accepted: true, txid` or `accepted: false, reason` (mempool admission mirrors the state machine's checks: nonce window, balance **including the 100-micro envelope fee**, duplicate nullifier, …); an accepted tx is also pushed to the node's gossip peers |
| `hk_mandateAvailable` | `leaf` (mandate id), `at?` (unix seconds; default chain time) | `available` (string, micro) — what the leaf may spend right now under every ancestor's drip and cap, or `null` + `reason` |
| `hk_getChannel` | `id` | `payer`, `payee`, `asset`, `mandate`, `tip`, `unit_price`, `max_steps`, `highest_step_settled`, `escrow_remaining`, `expiry`, `refunded` — a PayWord channel's full state |

Every envelope pays the protocol fee (`docs/FEES.md`): a transfer of `amount` needs `amount + fee.micro` available; the receipt for a shortfall is `rejected: insufficient balance for the protocol fee (have <a>, need <b>)` (fee) or `rejected: insufficient balance: have <a>, need <b>` (payload after the fee was debited).

## Shielded pool

| Method | Params | Result |
|---|---|---|
| `hk_getPoolInfo` | — | `version`, `asset`, `root` (current commitment-tree root), `latest_anchor`, `next_index`, `nullifiers` (count), `total_shielded` (string, micro — the pool's conservation ledger) |
| `hk_getPoolNotes` | — | `notes[{index, commitment, stealth_ct}]` — **the whole note index, no pagination** (wallets scan it by trial decapsulation; pagination is a plan item) |
| `hk_getPoolLeaves` | — | `leaves[hex…]` — the whole commitment list (same caveat) |
| `hk_nullifierSpent` | `nullifier` | `spent` (bool) |
| `hk_submitBundle` | `txs[]` (proof-less pool txs), `agg_proof` (hex, one aggregate STARK) | `accepted`, `txids[]` — the aggregator path (P2.3): one proof for every spend in the bundle |

## Operator

| Method | Params | Result |
|---|---|---|
| `hk_submitRotation` | `cert` (a root-signed `RotationCert`) | `accepted`, `epoch`, `queued` — queues a **foreign** validator's rotation certificate for this node's next proposal (the peer-carried revival path: `hk-node issue-rotation <HOME> <EPOCH>` produces the cert offline; any live node carries it in) |
| `hk_gossipTxs` | `txs[]` | `admitted`, `dropped` — peer ingress for transaction gossip (single hop: gossiped txs are admitted, never re-forwarded). Meant for validator-to-validator use over a firewalled RPC |

## Errors you will actually see

`unknown method: <name>` · `missing/invalid param: <name>` · `persistence disabled on this node (HK_NO_PERSIST)` · `rejected: …` receipts inside `hk_submitTx` results (the tx was *admitted or refused by the mempool*; a tx that is admitted but later refused in a block gets its `rejected:` string via `hk_getReceipt` / `hk_getTx`).

## Examples against testnet-1 (2026-09-03)

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
```

## Limits and refusals (v0.13.2)

Per request: 10 s to arrive in full (`408 request timed out`), 8 MiB body (`413`), 256 concurrent connections per node (`503 rpc busy`). **Operator methods are not browser-callable:** `hk_submitRotation`, `hk_gossipTxs` and `hk_submitBundle` answer `403` when the request carries an `Origin` header (a web page cannot drive a node's operator surface even when it can reach it); every other method, including `hk_submitTx`, keeps CORS `*`. `hk_submitBundle` queues at most 64 bundles and refuses a duplicate aggregate; `hk_gossipTxs` takes at most 1,024 txs per call. Still ledgered (`docs/P3.2-IMPLEMENTATION-PLAN.md`): no auth, no per-client rate limit · `hk_getPoolNotes`/`hk_getPoolLeaves` return the whole pool (pagination = H3) · `hk_getAccountTxs` turns any account id into its full transparent payment graph (by design of the transparent skeleton; shield if you need privacy).
