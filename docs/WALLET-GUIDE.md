# HashKinetics Wallet — user guide (Windows · v0.13.1 · testnet-1)

**What to click first, how to hide money, how to show it again, how to pay someone privately, and how to prove one payment to one person.** The same guide exists as a slide deck (`HashKinetics-Wallet-Guide.pptx` / `.pdf`, screenshots in `wallet-guide-shots/`); this is the text version for the repository and the website (`/wallet`). Everything here was done on the live network on 2026-09-02 — the transaction ids are real and searchable in the explorer.

> Test units only. Nothing in this wallet has monetary value, nothing is for sale, and the build is unsigned. Keys never leave your machine.

## 0 · Before you start

1. Download `HashKinetics-Wallet.exe` from the **v0.13.1 release** (`github.com/hashkinetics/hashkinetics/releases/tag/v0.13.1`, 6.4 MB). Screenshots below are from v0.13.0 — v0.13.1 adds the spend-key budget line and the version in the footer, nothing else moves.
2. Verify it — the only trust step: in PowerShell, `Get-FileHash .\HashKinetics-Wallet.exe` must print
   `FB330C291C656E71A7D3473F9CFFABB7A449A98EA7F8DDBCC09BD7062E16FB15`.
3. Windows SmartScreen will warn on first run (unsigned build): *More info → Run anyway*. Do not trust the popup either way — trust the hash.
4. The wallet talks to `https://rpc.hashkinetics.org` (chain), `https://faucet.hashkinetics.org` (test funds) and `https://prover.hashkinetics.org` (proofs). No installer, no registry, no admin rights.

**Every transaction pays the protocol fee: 0.000100, burned.** The wallet shows it under your balance and keeps it in mind for you (`docs/FEES.md`).

## 1 · Create or restore a wallet (first launch)

*Screenshot: `overview.jpg`*

- **Create my wallet** — generates a fresh seed on your machine and derives your account id. That's it; you are on the chain as soon as the faucet funds you (step 3).
- **Restore from a seed** (the collapsible below the button) — paste a 64-hex seed from a backup. The wallet refuses to overwrite an existing `account.json`; move the old one aside first.

The header shows the network the wallet is talking to: `wallet · hashkinetics-1-4e4ea68d`. If it says `connecting…` for more than a few seconds, check your internet — nothing is cached locally except your keys.

## 2 · The main screen

*Screenshot: `top_final.jpg`*

| Area | What it is |
|---|---|
| **ACCOUNT** | your 64-hex account id · `copy id` · `view on explorer ↗` — give the id to anyone who should pay you transparently |
| **BALANCE** | transparent balance in test units, with the chain's fee policy on the line below (`fee 0.000100 per tx · burned`) |
| **↻ Refresh** / **Get test funds** | refresh from the chain · ask the faucet for 0.100000 (once per IP per 24 h) |
| **SEND A PAYMENT** | a transparent transfer: recipient id, amount, `max` |
| **SHIELDED · …** | the private side (collapsed by default; step 5 onward) |
| **Backup & advanced** | seed, auth commitment, file locations |
| **ACTIVITY** | every action with its receipt and a `view ↗` link into the explorer |

## 3 · Get test funds

*Screenshot: `cooldown.jpg`*

Click **Get test funds**. The faucet creates your account on-chain (your first transaction is paid by the faucet's treasury) and drips **0.100000**. Within ~3 s the balance updates. A second click inside 24 hours shows the cooldown message — that's the faucet's per-address limit, not an error.

## 4 · Send a transparent payment

*Screenshots: `send_amount.jpg`, `send_max.jpg`, `send_receipt.jpg`*

1. Paste the recipient's account id (64 hex).
2. Type an amount — the line below shows exactly what will leave your account: `= 5000 micro + 100 fee`.
3. **max** fills in `balance − fee`; typing more than that greys out **Send** with *exceeds balance + fee* — the wallet refuses locally what the chain would refuse, so a doomed transaction never burns one of your one-time signing keys.
4. **Send** → the activity log shows `submitted <txid>` and, a few seconds later, the receipt `ok: 1 event(s)` with a `view ↗` link. Example on testnet-1: `7147b014…93087` (a 1,000.000000 transfer from the faucet treasury, block 2,199).

## 5 · Back up — both files

*Screenshot: `backup.jpg`*

Open **Backup & advanced**. Your keys live in `%USERPROFILE%\.hashkinetics\`:

- `account.json` — the transparent seed and your ratchet counter. `copy seed` puts the 64-hex seed on the clipboard; store it offline.
- `shield.json` — created the first time you shield. It holds the **shielded master** and two counters that must never run backwards (the one-time spend key index and the note tag). **Back it up too, and never restore an older copy over a newer one** — a reused one-time key would leak spend authority. Restoring the shielded side from the account seed alone is deliberately not offered.

## 6 · What "shielded" means here

Money in the **pool** is a set of hash-committed notes; who owns which note, and how much it is, is invisible to the chain and to the explorer. Spending a note produces a STARK proof (made for you by the public prover, verified by every validator) and a **nullifier** that prevents the note being spent twice — without revealing which note it was. The explorer shows the pool's total and the nullifier count, nothing else. There is no master view key anywhere in the design; disclosure is one payment, one time, to one party (step 11).

Proofs take a while (typically 3–15 s on the public prover, longer under load). The wallet shows a spinner and keeps working; it never blocks the UI.

## 7 · Shield (hide): transparent → pool

*Screenshots: `shield_typed.jpg`, `proving.jpg`, `proof_ready.jpg`*

Open the **SHIELDED** panel. Type an amount next to **Shield → pool** and click it. The wallet reserves a spend key, asks the prover for a *mint* proof, submits, and logs the receipt. Your transparent balance drops by `amount + fee`; the panel's title now reads `SHIELDED · 0.050000 in 1 note(s)`. Example: `944362aa…4688` (block 1,650).

## 8 · Scan the pool and your stealth address

*Screenshots: `shielded_panel.jpg`, `notes_first.jpg`*

**↻ Scan pool** downloads the pool's note index and trial-decrypts every note with your key — only yours open. Each note shows `LIVE` or `SPENT`, its value, the memo (if a payer attached one) and `#index cm…`. **copy my stealth address** copies your `hkaddr:…` — give it to anyone who should pay you *privately*. Nobody can link a stealth address to your account id.

## 9 · Unshield (show): pool → me

*Screenshots: `unshield_typed.jpg`, `unshield_receipt.jpg`*

Type an amount next to **Pool → me** and click it. The wallet picks one note that covers it, proves the spend, and the amount lands in your transparent balance; any remainder comes back to you as a fresh hidden note (change). Example: `5696eeba…` (a partial unshield with change).

## 10 · Pay shielded (private payment with a memo)

*Screenshots: `pay_fields.jpg`, `pay_receipt.jpg`, `notes_after_pay.jpg`*

Paste the recipient's `hkaddr:…`, an amount and an optional memo, click **Pay shielded**. The chain sees a nullifier and two new commitments — not who paid whom, not how much. The recipient finds the note on their next scan, memo intact. Example: `22082712…` (2026-09-02, memo delivered).

## 11 · Receive privately

Nothing to do: share your stealth address (step 8) and scan. Notes appear as `LIVE` with the sender's memo. You can spend them straight away (steps 9–10) — one input note per spend, so consolidate by paying yourself if you need a larger single note.

## 12 · Disclose one payment to one person

Every note has a **disclose** button. It writes `disclosure-<id>.json` next to your keys: the note's value, memo and anchor, bound to that single commitment — nothing else in the pool opens with it. Send the file to the party who needs to see that payment; they verify it fully **offline** with `hk-node verify-disclosure disclosure-<id>.json` (exit code 0 = verified). The same file opens zero other notes — that is the point.

## 13 · Fees, refusals and the `max` button

*Screenshots: `send_max.jpg`, `activity_final.jpg`*

- The fee is always paid from the **transparent** side, even for shielded operations — keep at least 0.001000 visible if you plan to move hidden money.
- `max` = balance − fee. Anything above it is refused locally.
- If the chain refuses anyway (someone else spent first, a stale nonce, a shortfall the wallet could not see), the activity log explains the receipt in plain words and your funds are untouched — a refused transaction never moves money, fee included.

## 14 · Where things live · troubleshooting

| Symptom | Meaning | Do |
|---|---|---|
| header says `connecting…` | no RPC reply | check internet; try ↻ Refresh |
| **Get test funds** says cooldown | one drip per IP per 24 h | wait, or ask a friend to send you some |
| spinner for a long time on a shielded op | the prover is proving (up to 15 min under load) | wait; the receipt lands in ACTIVITY |
| `shield.json` error about capacity | 64 one-time spend keys used on this master | move `shield.json` aside (keep it!) and shield again with a fresh master — old notes stay spendable from the old file |
| a payment shows `rejected: …` | the chain refused it — the log says why | nothing was spent; fix the cause and retry |

Files: `%USERPROFILE%\.hashkinetics\account.json` · `shield.json` · `disclosure-*.json`. The prover URL field defaults to `https://prover.hashkinetics.org`; point it at your own `hk-prove` if you run one.

## 15 · What this wallet is — and is not

It is a real client of a real post-quantum chain: every transaction you make is a hash-signed consensus transaction, every shielded operation is a real STARK verified by every validator, and the receipts above are searchable in the explorer. It is **not** audited, **not** code-signed, and it holds **test units** on **testnet-1** — balances from the retired staging-1 network did not carry over (same seed, re-fund through the faucet). Keys sit in plaintext JSON on your disk (passphrase protection is on the plan). No master view key exists, ever.
