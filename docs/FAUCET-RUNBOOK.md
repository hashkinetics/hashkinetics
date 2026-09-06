# Faucet runbook — hot/cold, low-watermark, sealed keys (K3, node v0.16.0)

The public faucet (`hk-node faucet-serve`, https://faucet.hashkinetics.org) is the front
door of the chain: it turns an auth commitment into a funded account. Until v0.15.x it
signed straight from the genesis treasury account. From v0.16.0 it is run as a **hot
wallet with a small float**, refilled by hand from a **cold treasury** that is never on
the faucet host. This page is the whole procedure; nothing here is specific to our fleet.

## 1 · The shape

```
cold treasury (account-new, sealed, offline machine)  ──account-send──▶  hot faucet float (sealed, on the faucet host)
                                                                            │
                                                                       faucet-serve ──drip──▶ new accounts
```

- **Hot** = the directory `faucet-serve` runs on. Holds `account.json` (sealed) and
  `faucet-cooldowns.json`. Balance target: a few days of drips (see §3).
- **Cold** = the genesis treasury (or any funded account) on a machine that is not the
  faucet host. Its `account.json` is sealed; it signs one transfer per refill and nothing
  else. The old rule "stop the faucet before a treasury send" is gone — two accounts, two
  signers, no shared nonce.
- Both use the same envelope (`HKE1`, `docs/MAINNET-KEY-MANAGEMENT.md` → keys at rest);
  the faucet service takes its passphrase from a systemd credential, the cold wallet
  from a prompt. The cold treasury should also use a key file (`hk-node keyfile-new`,
  `HK_WALLET_KEYFILE=…` at seal time and at every send) kept apart from its backup.

## 2 · Set-up (once)

```bash
# on the faucet host, as the service user — this is how testnet-1's faucet was set up:
# the hot passphrase is generated straight into a file, never typed, never on a command line
hk-node account-new ~/hk-faucet-hot                    # prints the auth commitment (nonce-0)
umask 077; hk-node passphrase-new > ~/.hot.pass
HK_WALLET_PASSPHRASE="$(cat ~/.hot.pass)" hk-node account-seal ~/hk-faucet-hot
sudo install -d -m 0700 /etc/hk
sudo install -m 0600 -o root -g root ~/.hot.pass /etc/hk/faucet-passphrase && shred -u ~/.hot.pass

# on the cold machine (the treasury directory, sealed with a passphrase you choose at the prompt AND a key file)
hk-node keyfile-new ~/.hk-treasury.key
HK_WALLET_KEYFILE=~/.hk-treasury.key hk-node account-seal ~/hk-treasury
# fund the hot account: create it with the float in one transaction
HK_WALLET_KEYFILE=~/.hk-treasury.key \
hk-node account-create ~/hk-treasury https://rpc.hashkinetics.org <HOT-AUTH-COMMIT-hex> 5000000000   # $5,000 test units
```
(The credential file is the only copy of the hot passphrase on the host; keep a second copy off-host —
without it a reinstalled faucet cannot open its own float. The float is small on purpose.)
`/etc/systemd/system/hk-faucet.service`:
```ini
[Service]
User=hk
LoadCredential=hk-wallet-passphrase:/etc/hk/faucet-passphrase
Environment=HK_FAUCET_LOW_MICRO=1000000000        # $1,000 — the refill signal
Environment=HK_FAUCET_RESERVE_MICRO=200000        # 2 drips — where drips stop (503)
ExecStart=/home/hk/bin/hk-node faucet-serve /home/hk/hk-faucet-hot http://127.0.0.1:26000 --listen 127.0.0.1:9922 --drip 100000
Restart=always
```
Defaults if unset: low watermark = 50 drips, reserve = 2 drips (both derived from `--drip`).
Flags `--low-micro` / `--reserve-micro` override the environment.

## 3 · Sizing the float

Drips per day is bounded by `--daily-cap` (default 200) — so the float can never drain
faster than `daily_cap × drip` per day. With the defaults ($0.10 drip, 200/day) that is
$20/day; a $5,000 float is months, a $1,000 watermark is weeks of warning. Bigger drips or
caps: scale the float so the watermark is ≥ 7 days of the cap.

## 4 · Watching it — `/health`

```json
{ "ok": true, "faucet_account": "…", "faucet_balance_micro": 4321000000, "drip_micro": 100000,
  "fee": {…}, "low": false, "low_watermark_micro": 1000000000, "reserve_micro": 200000, "drips_left": 43208 }
```
- `low: true` → refill (§5). The site's faucet page can show it; an uptime checker can
  alert on the string `"low":true`.
- `drips_left` = `(balance − reserve) / drip`, the human number.
- Below `reserve + drip` the faucet answers **503 "faucet is being refilled"** and burns
  nothing — no ratchet index is spent on a transfer the chain would refuse.
- The service log says `⚠ faucet low:` on every drip under the watermark and `⚠ faucet
  dry:` on every refusal.

## 5 · Refill (from the cold machine, any time, no faucet restart)

```bash
HK_WALLET_PASSPHRASE_FILE=~/.hk-treasury-pass \
hk-node account-send ~/hk-treasury https://rpc.hashkinetics.org <HOT-ACCOUNT-ID-hex> 4000000000
curl -s https://faucet.hashkinetics.org/health | grep -o '"low":[a-z]*'
```
Post the txid in `#receipts` — a refill is a public event on a public chain anyway.

## 6 · Rotating the hot account

If the faucet host is ever suspected compromised: make a new hot account (§2), fund it
with a small float, repoint the unit, restart; sweep whatever is left in the old hot
account back to the treasury with `account-send` from a copy of its (sealed) directory.
The cold treasury never changes and never touched that host.

## 7 · What is and is not protected

Sealed `account.json` protects a copied disk, a leaked backup, a stray `cat`. It does not
protect a running service: the seed is in memory while it signs. That is why the float is
small and the treasury is elsewhere — the blast radius of a hot-host compromise is one
float, not the treasury.
