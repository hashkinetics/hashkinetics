# HashKinetics Wallet — user guide (Windows v0.14.1 · Android v0.2.0 · testnet-1)

**What to click first, how to hide money, how to show it again, how to pay someone privately, and how to prove one payment to one person.** The same guide exists as a slide deck (`HashKinetics-Wallet-Guide.pptx` / `.pdf`, screenshots in `wallet-guide-shots/`); this is the text version for the repository and the website (`/wallet`). Everything here was done on the live network on 2026-09-02 — the transaction ids are real and searchable in the explorer.

> Test units only. Nothing in this wallet has monetary value, nothing is for sale; the Windows build is unsigned (verify the hash), the Android build is signed with the HashKinetics release key (verify the hash and the signer). Keys never leave your machine — or your phone.

## 0 · Before you start

1. Download `HashKinetics-Wallet.exe` from the **v0.16.1 release** (`github.com/hashkinetics/hashkinetics/releases/tag/v0.16.1` — wallet v0.14.1, 6.6 MB). Screenshots below are from v0.13.x; v0.14.0 added *Protect with a passphrase* (§5a), v0.14.1 the incremental scan (§8) — the screens are otherwise the same.
2. Verify it — the only trust step: in PowerShell, `Get-FileHash .\HashKinetics-Wallet.exe` must print
   `17566A9E5CC258814F06924C65334631F62205358823414F4ABAF587E5F8308E` (v0.14.1; the v0.13.1 build was `FB330C29…`).
3. Windows SmartScreen will warn on first run (unsigned build): *More info → Run anyway*. Do not trust the popup either way — trust the hash.
4. The wallet talks to `https://rpc.hashkinetics.org` (chain), `https://faucet.hashkinetics.org` (test funds) and `https://prover.hashkinetics.org` (proofs). No installer, no registry, no admin rights.

**Every transaction pays the protocol fee: 0.000100, burned.** The wallet shows it under your balance and keeps it in mind for you (`docs/FEES.md`).

## 0a · Android (v0.2.0)

The same wallet as a phone app — the desktop's Rust library called through UniFFI, the same `account.json` / `shield.json` / `disclosure-*.json` (a phone backup restores on a PC and vice-versa). Release: [`wallet-android-v0.2.0`](https://github.com/hashkinetics/hashkinetics/releases/tag/wallet-android-v0.2.0).

1. **Download** `HashKinetics-Wallet-android-0.2.0.apk` from the release. Android 8.0 or newer on a 64-bit phone (arm64-v8a).
2. **Verify** — two checks, both published on the release page: `sha256sum HashKinetics-Wallet-android-0.2.0.apk` → `3510d1c8bad8506ff406ea64ae6a7a7a06a3b68e2a6ec4539b0cdda6919d3904`; `apksigner verify --print-certs HashKinetics-Wallet-android-0.2.0.apk` (Android build-tools) → signer certificate SHA-256 `b296799ed6bea902f6a30ed3bcd497adce7374eb15ec9f8d587ef0575902d6d3`. Every future release is signed by the same key (valid to 2054), so Android upgrades it in place; a build whose signer differs is not ours.
3. **Install** (sideload): allow "install unknown apps" for your browser or file manager, open the APK. If a `-debug` build from a workflow artifact is on the phone, uninstall it first — different key; that deletes its testnet wallet.
4. **Four screens behind a bottom bar** — *Wallet* (balance, fee, height · Refresh · Get test funds · Receive with a QR of your account id · Send), *Shielded* (stealth address with a QR · Scan · notes · Shield / Unshield · Pay shielded with a memo · Disclose one payment), *Backup* (Show seed · passphrase Protect / Change / Lock · device lock · key-file export), *Activity* (every core call's report, with explorer links). Before a wallet exists the app shows *Welcome* (Create keychain / Restore from a 64-hex seed); while the files are sealed it shows *Unlock*. §1–§13 below apply unchanged.
5. **What is different on a phone.** *Protect* seals both files with Argon2id at **256 MiB** (the desktop uses 512 MiB; the parameters ride in the envelope, so either side opens the other's files). **Device lock** (off by default): a 32-byte key file wrapped by an AES-GCM key in the Android Keystore becomes a second factor — the sealed files then need this phone, or the exported key file (`HK_WALLET_KEYFILE` on a PC), as well as the passphrase; re-protect after switching it. Files live in the app's private storage (`files/wallet/`), cloud backup of them is disabled (`allowBackup=false`) — write the seed down, export `shield.json` yourself (it cannot be re-derived).
6. **Not yet:** camera QR scanning and biometric key release (v0.3), in-app proving (the public prover proves for you; a shielded operation takes a minute or two), iOS, a Play Store listing (after the first month). Unaudited testnet software.

Source: `android/` (Kotlin + Jetpack Compose) over `chain/crates/hk-wallet-core` (Rust); built and signed by `.github/workflows/wallet-android.yml`; gate `chain/gate-wa1.sh` (the whole journey on a devnet + the CLI opening the phone's sealed files).

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

### 5a · Protect with a passphrase (wallet v0.14.0)

Under **Backup & advanced → Protect with a passphrase**, type a passphrase twice — 12+ characters, or a passphrase of 4+ words; **generate** gives you seven random words (write them down) — and click **Protect this wallet**. From then on both files are stored **encrypted** (Argon2id 512 MiB → XChaCha20-Poly1305; the file starts with `"hke": 1` instead of your seed), and the wallet opens to an **Unlock** screen. Unlocking takes about a second (that is the brute-force cost, paid once); everything after is instant. The passphrase is kept in memory for the session only.

- A copied `account.json` / `shield.json` is useless without the passphrase. A running, unlocked wallet still holds the keys in memory — lock your screen, not just the wallet.
- **There is no recovery.** Forget the passphrase and the files are gone; the 64-hex **seed backup** from §5 is what brings the transparent account back (the shielded side follows the rule above — keep a copy of `shield.json` from *before* you protected it, or unprotect, back up, re-protect).
- **How hard is it to guess?** A copied file lets an attacker try passphrases offline; each try costs 512 MiB of memory and about a second of work, so even a GPU manages tens of guesses per second. Weak passphrases are refused (short, common words with digits, keyboard walks); seven generated words are 63 bits — beyond any offline attack at that cost. A key file (`HK_WALLET_KEYFILE=<path>` set when you protect and when you unlock; make one with `hk-node keyfile-new`) adds a second factor the backup never carries.
- The CLI reads the same envelope: `hk-node account-*` and `wallet` commands on a protected directory take the passphrase from `HK_WALLET_PASSPHRASE`, `HK_WALLET_PASSPHRASE_FILE` or a prompt, and `hk-node account-seal DIR` / `account-unseal DIR` do the same conversion from a terminal.
- **Remove passphrase (write plain files)** puts plain JSON back on disk; **Change** re-seals under a new one (the old one must be loaded — the wallet is unlocked).

## 6 · What "shielded" means here

Money in the **pool** is a set of hash-committed notes; who owns which note, and how much it is, is invisible to the chain and to the explorer. Spending a note produces a STARK proof (made for you by the public prover, verified by every validator) and a **nullifier** that prevents the note being spent twice — without revealing which note it was. The explorer shows the pool's total and the nullifier count, nothing else. There is no master view key anywhere in the design; disclosure is one payment, one time, to one party (step 11).

Proofs take a while (typically 3–15 s on the public prover, longer under load). The wallet shows a spinner and keeps working; it never blocks the UI.

## 7 · Shield (hide): transparent → pool

*Screenshots: `shield_typed.jpg`, `proving.jpg`, `proof_ready.jpg`*

Open the **SHIELDED** panel. Type an amount next to **Shield → pool** and click it. The wallet reserves a spend key, asks the prover for a *mint* proof, submits, and logs the receipt. Your transparent balance drops by `amount + fee`; the panel's title now reads `SHIELDED · 0.050000 in 1 note(s)`. Example: `944362aa…4688` (block 1,650).

## 8 · Scan the pool and your stealth address

*Screenshots: `shielded_panel.jpg`, `notes_first.jpg`*

**↻ Scan pool** reads the pool's note index and trial-decrypts every note with your key — only yours open. Since v0.14.1 the scan is *incremental*: the wallet remembers how far it has read and which notes are yours (inside `shield.json`, sealed with it when the wallet is protected), so a scan costs only what the pool appended since — the ACTIVITY line says how many new entries it read. A wallet moved to another network, or restored from an older `shield.json`, simply scans once from the start. Each note shows `LIVE` or `SPENT`, its value, the memo (if a payer attached one) and `#index cm…`. **copy my stealth address** copies your `hkaddr:…` — give it to anyone who should pay you *privately*. Nobody can link a stealth address to your account id.

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
| `the path does not fold to the stated root` | the node answered a bad Merkle path (v0.14.1 asks the node for one path per spend and re-checks it) | nothing was spent; ↻ Scan and retry, or point `HK_WALLET_RPC` at another node |
| a note you know you received is missing after a scan | the scan cache is behind or from another network | ACTIVITY shows the pool size read; if it looks wrong, remove the `scan` block from `shield.json` (or the whole cache — never the seed) and scan again from the start |
| opens to **This wallet is protected** | the files are sealed (v0.14.0) | type the passphrase; there is no reset — use the seed backup if it is lost |
| `Could not unlock: wrong passphrase` | typo, or a file was tampered with | retry; the wallet never half-opens a sealed file |

Files: `%USERPROFILE%\.hashkinetics\account.json` · `shield.json` · `disclosure-*.json` (Android: the app's private `files/wallet/`, plus `files/keyfile.bin` when the device lock is on). The prover URL field defaults to `https://prover.hashkinetics.org`; point it at your own `hk-prove` if you run one.

## 15 · What this wallet is — and is not

It is a real client of a real post-quantum chain: every transaction you make is a hash-signed consensus transaction, every shielded operation is a real STARK verified by every validator, and the receipts above are searchable in the explorer. It is **not** audited; the Windows build is **not** code-signed (the Android APK is signed with the HashKinetics release key — verify the digest), and it holds **test units** on **testnet-1** — balances from the retired staging-1 network did not carry over (same seed, re-fund through the faucet). Keys sit in JSON on your disk or in the app's private storage — plain by default, sealed with a passphrase if you choose (v0.14.0 / Android v0.2.0, §5a / §0a). No master view key exists, ever.
