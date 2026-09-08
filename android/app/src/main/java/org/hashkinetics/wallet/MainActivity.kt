package org.hashkinetics.wallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.hashkinetics.wallet.core.NoteView
import org.hashkinetics.wallet.ui.Bg
import org.hashkinetics.wallet.ui.ControlShape
import org.hashkinetics.wallet.ui.CopyRow
import org.hashkinetics.wallet.ui.Cyan
import org.hashkinetics.wallet.ui.Danger
import org.hashkinetics.wallet.ui.Faint
import org.hashkinetics.wallet.ui.Field
import org.hashkinetics.wallet.ui.GhostButton
import org.hashkinetics.wallet.ui.Gold
import org.hashkinetics.wallet.ui.Hint
import org.hashkinetics.wallet.ui.HkTheme
import org.hashkinetics.wallet.ui.Ink
import org.hashkinetics.wallet.ui.Kicker
import org.hashkinetics.wallet.ui.Line
import org.hashkinetics.wallet.ui.Mono
import org.hashkinetics.wallet.ui.Muted
import org.hashkinetics.wallet.ui.Ok
import org.hashkinetics.wallet.ui.Panel
import org.hashkinetics.wallet.ui.PanelShape
import org.hashkinetics.wallet.ui.Pill
import org.hashkinetics.wallet.ui.PrimaryButton
import org.hashkinetics.wallet.ui.Qr
import org.hashkinetics.wallet.ui.Surface1
import org.hashkinetics.wallet.ui.Surface2
import org.hashkinetics.wallet.ui.Violet
import org.hashkinetics.wallet.ui.Wordmark

/**
 * WA2 v0.2 — one Activity, the brand theme, four sections behind a bottom bar: Wallet (balance, receive,
 * send) · Shielded (stealth address, scan, notes, shield / unshield / pay / disclose) · Backup (seed,
 * passphrase, device lock) · Activity (what the core reported). Before a wallet exists: Welcome; while it
 * is sealed: Unlock. Every button hands one call to the ViewModel; nothing here touches the core directly.
 */
class MainActivity : ComponentActivity() {
    private val vm: WalletVm by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Bg.toArgb()), navigationBarStyle = SystemBarStyle.dark(Bg.toArgb()))
        super.onCreate(savedInstanceState)
        setContent { HkTheme { WalletApp(vm) } }
    }
}

private enum class Section(val label: String, val icon: ImageVector) {
    Wallet("Wallet", Icons.Filled.Home),
    Shielded("Shielded", Icons.Filled.Lock),
    Backup("Backup", Icons.Filled.Settings),
    Activity("Activity", Icons.AutoMirrored.Filled.List),
}

@Composable
fun WalletApp(vm: WalletVm) {
    val ctx = LocalContext.current
    val st = vm.state
    var tab by rememberSaveable { mutableStateOf(0) }
    val home = st != null && st.exists && !st.locked
    Scaffold(
        containerColor = Bg,
        topBar = { Header(vm) },
        bottomBar = { if (home) BottomBar(tab) { tab = it } },
    ) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            vm.busy?.let { BusyLine(it) }
            vm.error?.let { ErrorBanner(it) { vm.clearError() } }
            when {
                st == null -> Hint("…")
                !st.exists -> WelcomeScreen(vm)
                st.locked -> UnlockScreen(vm, st.needsKeyfile)
                else -> when (Section.entries[tab]) {
                    Section.Wallet -> WalletTab(vm)
                    Section.Shielded -> ShieldedTab(vm)
                    Section.Backup -> BackupTab(vm)
                    Section.Activity -> ActivityTab(vm) { url -> ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                }
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

// ---- chrome ----------------------------------------------------------------------------------------

@Composable
private fun Header(vm: WalletVm) {
    Row(
        Modifier.fillMaxWidth().background(Bg).statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(painterResource(R.drawable.hk_mark), contentDescription = null, modifier = Modifier.size(40.dp))
        Spacer(Modifier.width(10.dp))
        Column {
            Wordmark(13.5.sp)
            Text("wallet 0.2.0 · core ${vm.coreVersion}", color = Faint, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
        Spacer(Modifier.weight(1f))
        Pill("TESTNET-1")
    }
}

@Composable
private fun BottomBar(selected: Int, onSelect: (Int) -> Unit) {
    NavigationBar(containerColor = Surface1, contentColor = Muted) {
        Section.entries.forEachIndexed { i, s ->
            NavigationBarItem(
                selected = selected == i,
                onClick = { onSelect(i) },
                icon = { Icon(s.icon, contentDescription = s.label) },
                label = { Text(s.label, fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Cyan, selectedTextColor = Cyan, indicatorColor = Surface2,
                    unselectedIconColor = Muted, unselectedTextColor = Muted,
                ),
            )
        }
    }
}

@Composable
private fun BusyLine(label: String) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth().clip(ControlShape), color = Cyan, trackColor = Surface2)
        Text(label, color = Cyan, fontSize = 12.sp)
    }
}

@Composable
private fun ErrorBanner(msg: String, dismiss: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().background(Danger.copy(alpha = 0.10f), PanelShape).border(1.dp, Danger.copy(alpha = 0.5f), PanelShape)
            .padding(start = 14.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(msg, color = Danger, fontSize = 13.sp, modifier = Modifier.weight(1f))
        TextButton(onClick = dismiss) { Text("dismiss", color = Danger) }
    }
}

// ---- before a wallet exists / while sealed --------------------------------------------------------

@Composable
private fun WelcomeScreen(vm: WalletVm) {
    var seed by remember { mutableStateOf("") }
    Column(Modifier.fillMaxWidth().padding(top = 16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Image(painterResource(R.drawable.hk_mark), contentDescription = null, modifier = Modifier.size(112.dp))
        Wordmark(18.sp)
        Text("The quantum-proof private settlement rail.", color = Muted, fontSize = 14.sp, textAlign = TextAlign.Center)
        Spacer(Modifier.height(4.dp))
        Panel("New wallet") {
            Hint("Keys are born on this phone and never leave it. Back the seed up once it exists; the shielded side is a file you export.")
            PrimaryButton("Create keychain", vm.busy == null, Modifier.fillMaxWidth()) { vm.create() }
        }
        Panel("Restore", Violet) {
            Field(seed, { seed = it }, "Seed (64 hex characters)", mono = true)
            GhostButton("Restore keychain", vm.busy == null && seed.trim().length == 64, Modifier.fillMaxWidth(), Violet) { vm.restore(seed) }
        }
        Text("Unaudited testnet software · nothing here is for sale", color = Faint, fontSize = 11.sp, textAlign = TextAlign.Center)
    }
}

@Composable
private fun UnlockScreen(vm: WalletVm, needsKeyfile: Boolean) {
    var pass by remember { mutableStateOf("") }
    Column(Modifier.fillMaxWidth().padding(top = 16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Image(painterResource(R.drawable.hk_mark), contentDescription = null, modifier = Modifier.size(96.dp))
        Wordmark(18.sp)
        Panel("Sealed", Gold) {
            Hint(if (needsKeyfile) "This wallet is sealed with a passphrase and this device's key file." else "This wallet is sealed with a passphrase (Argon2id, once per session).")
            Field(pass, { pass = it }, "Passphrase", password = true)
            PrimaryButton("Unlock", vm.busy == null && pass.isNotEmpty(), Modifier.fillMaxWidth()) { vm.unlock(pass); pass = "" }
        }
    }
}

// ---- Wallet ----------------------------------------------------------------------------------------

@Composable
private fun WalletTab(vm: WalletVm) {
    BalanceCard(vm)
    vm.state?.accountId?.let { ReceiveCard(it) }
    SendCard(vm)
}

@Composable
private fun BalanceCard(vm: WalletVm) {
    val s = vm.status
    Column(
        Modifier.fillMaxWidth().background(Surface1, PanelShape)
            .border(1.dp, Brush.linearGradient(listOf(Cyan.copy(alpha = 0.8f), Violet.copy(alpha = 0.8f))), PanelShape)
            .padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Kicker("Balance")
        if (s == null) {
            Text("—", color = Ink, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold)
            Hint("Refresh reads the chain.")
        } else {
            Row(verticalAlignment = Alignment.Bottom) {
                Text(vm.formatMicro(s.balanceMicro), color = Ink, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(8.dp))
                Text("HKN", color = Cyan, fontSize = 14.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 7.dp))
            }
            if (s.onChain) Hint("fee ${vm.formatMicro(s.feeMicro)} per tx · max sendable ${vm.formatMicro(s.maxSendableMicro)}")
            else Hint("Not on-chain yet — Get test funds creates and funds the account.", Gold)
            Text("${s.chainId} · height ${s.height} · node ${s.nodeVersion}", color = Faint, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            GhostButton("Refresh", vm.busy == null, Modifier.weight(1f)) { vm.refresh() }
            PrimaryButton("Get test funds", vm.busy == null, Modifier.weight(1f)) { vm.faucet() }
        }
    }
}

@Composable
private fun ReceiveCard(id: String) {
    Panel("Receive", Violet) {
        Hint("Your account id — share it (or the code) to receive HKN.")
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Qr(id) }
        Mono(id)
        CopyRow("account id · 64 hex", id)
    }
}

@Composable
private fun SendCard(vm: WalletVm) {
    var to by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    Panel("Send") {
        Field(to, { to = it }, "To — account id (64 hex)", mono = true)
        Field(amount, { amount = it }, "Amount, e.g. 0.25")
        PrimaryButton("Send", vm.busy == null && to.trim().length == 64 && amount.isNotBlank(), Modifier.fillMaxWidth()) { vm.send(to, amount) }
    }
}

// ---- Shielded --------------------------------------------------------------------------------------

@Composable
private fun ShieldedTab(vm: WalletVm) {
    val sc = vm.scan
    var amount by remember { mutableStateOf("") }
    var payTo by remember { mutableStateOf("") }
    var payAmount by remember { mutableStateOf("") }
    var memo by remember { mutableStateOf("") }
    var commitment by remember { mutableStateOf("") }

    Panel("Shielded pool", Violet) {
        Hint("Balances and counterparties in the pool are invisible on-chain; the fee is paid from the transparent balance. Proofs are made on the prover — a shielded operation takes a minute or two.")
        if (sc != null) {
            val hidden = sc.notes.filter { !it.spent }.fold(0UL) { acc, n -> acc + n.valueMicro }
            Row(verticalAlignment = Alignment.Bottom) {
                Text(vm.formatMicro(hidden), color = Ink, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(8.dp))
                Text("HKN hidden", color = Violet, fontSize = 13.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 5.dp))
            }
            Text("${sc.unspent} unspent note(s) · pool ${sc.poolSize} · one-time spends ${sc.otsUsed}/${sc.otsCapacity}", color = Faint, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
        GhostButton(if (sc == null) "Scan the pool" else "Rescan", vm.busy == null, Modifier.fillMaxWidth(), Violet) { vm.scanPool() }
    }

    if (sc != null) {
        Panel("Receive shielded", Violet) {
            Hint("Your stealth address for the chain's current epoch — share it to be paid in the pool.")
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Qr(sc.stealthAddress) }
            Mono(sc.stealthAddress)
            CopyRow("stealth address", sc.stealthAddress)
        }
        if (vm.notes.isNotEmpty()) Panel("Notes", Violet) {
            vm.notes.forEachIndexed { i, n ->
                if (i > 0) HorizontalDivider(color = Line)
                NoteRow(vm, n)
            }
        }
    }

    Panel("Shield · unshield") {
        Field(amount, { amount = it }, "Amount")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PrimaryButton("Shield", vm.busy == null && amount.isNotBlank(), Modifier.weight(1f)) { vm.shield(amount) }
            GhostButton("Unshield", vm.busy == null && amount.isNotBlank(), Modifier.weight(1f)) { vm.unshield(amount) }
        }
    }

    Panel("Pay shielded", Violet) {
        Field(payTo, { payTo = it }, "To — hkaddr:…", mono = true)
        Field(payAmount, { payAmount = it }, "Amount")
        Field(memo, { memo = it }, "Memo (sealed to the recipient)")
        PrimaryButton("Pay shielded", vm.busy == null && payTo.trim().startsWith("hkaddr:") && payAmount.isNotBlank(), Modifier.fillMaxWidth()) { vm.payShielded(payTo, payAmount, memo) }
    }

    Panel("Disclose one payment", Gold) {
        Hint("An auditor package for one received note: value, memo and the on-chain commitment, verifiable with hk-node verify-disclosure.")
        Field(commitment, { commitment = it }, "Commitment (64 hex)", mono = true)
        GhostButton("Build package", vm.busy == null && commitment.trim().length == 64, Modifier.fillMaxWidth(), Gold) { vm.disclose(commitment) }
        vm.lastDisclosure?.let {
            Hint("Package (also saved next to the wallet files):")
            Mono(it.take(600) + if (it.length > 600) "…" else "", Muted, 11.sp)
        }
    }
}

@Composable
private fun NoteRow(vm: WalletVm, n: NoteView) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(vm.formatMicro(n.valueMicro), color = if (n.spent) Faint else Ink, fontSize = 15.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
            Pill(if (n.spent) "SPENT" else "UNSPENT", if (n.spent) Faint else Ok)
        }
        Text("leaf ${n.leafIndex}" + if (n.memo.isNotEmpty()) "  ·  “${n.memo}”" else "", color = Muted, fontSize = 12.sp)
        Mono(n.commitment, Faint, 10.sp)
    }
}

// ---- Backup ----------------------------------------------------------------------------------------

@Composable
private fun BackupTab(vm: WalletVm) {
    var pass by remember { mutableStateOf("") }
    val st = vm.state
    val sealed = st?.sealed == true
    val hasPass = st?.`protected` == true

    Panel("Seed", Gold) {
        Hint("The seed restores the transparent account anywhere. shield.json (in this app's files) is the shielded side and must be backed up as a file — it cannot be re-derived. Write the seed down; never screenshot it.")
        if (vm.seedShown == null) {
            GhostButton("Show seed", vm.busy == null, Modifier.fillMaxWidth(), Gold) { vm.showSeed() }
        } else {
            Mono(vm.seedShown!!)
            TextButton(onClick = { vm.hideSeed() }) { Text("hide", color = Gold) }
        }
    }

    Panel("Passphrase", if (sealed) Cyan else Gold) {
        Hint(if (sealed) "Files are sealed on disk (HKE1, Argon2id 256 MiB)." else "Files are PLAIN on disk — set a passphrase.", if (sealed) Ok else Gold)
        Field(pass, { pass = it }, if (hasPass) "New passphrase" else "Passphrase (≥ 12 chars or 4+ words)", password = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PrimaryButton(if (hasPass) "Change" else "Protect", vm.busy == null && pass.isNotEmpty(), Modifier.weight(1f)) { vm.protect(pass); pass = "" }
            GhostButton("Generate 7 words", vm.busy == null, Modifier.weight(1f)) { pass = vm.generatePassphrase() }
        }
        if (hasPass) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            GhostButton("Lock now", vm.busy == null, Modifier.weight(1f)) { vm.lock() }
            GhostButton("Remove passphrase", vm.busy == null, Modifier.weight(1f), Danger) { vm.unprotect() }
        }
    }

    Panel("Device lock") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Key file in the Android Keystore", color = Ink, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                Hint("On: the sealed files need this device too — export the key file before restoring elsewhere. Re-protect after switching.")
            }
            Spacer(Modifier.width(12.dp))
            Switch(
                checked = vm.deviceLock, onCheckedChange = { vm.toggleDeviceLock(it) }, enabled = vm.busy == null,
                colors = SwitchDefaults.colors(checkedThumbColor = Bg, checkedTrackColor = Cyan, uncheckedThumbColor = Muted, uncheckedTrackColor = Surface2, uncheckedBorderColor = Line),
            )
        }
        if (vm.deviceLock) vm.exportKeyfileHex()?.let {
            Hint("Key file (HK_WALLET_KEYFILE on a PC):")
            Mono(it, Muted, 11.sp)
            CopyRow("32 bytes, hex", it)
        }
    }

    Panel("Files on this phone") {
        Hint("filesDir/wallet/account.json · shield.json · disclosure-*.json — byte-compatible with the desktop wallet and hk-node account-*. No cloud backup is ever made of them.")
    }
}

// ---- Activity --------------------------------------------------------------------------------------

@Composable
private fun ActivityTab(vm: WalletVm, open: (String) -> Unit) {
    Panel("Activity") {
        if (vm.log.isEmpty()) Hint("Nothing yet — every call into the core reports here.", Faint)
        vm.log.take(80).forEach { l ->
            val color: Color = when (l.level) { "ok" -> Ok; "error" -> Danger; else -> Muted }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                Text(l.time, color = Faint, fontSize = 11.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(end = 10.dp, top = 2.dp))
                Column(Modifier.weight(1f)) {
                    Text(l.text, color = color, fontSize = 12.sp, lineHeight = 16.sp)
                    l.link?.let { TextButton(onClick = { open(it) }, contentPadding = PaddingValues(0.dp)) { Text("open in explorer", fontSize = 11.sp, color = Cyan) } }
                }
            }
        }
    }
}
