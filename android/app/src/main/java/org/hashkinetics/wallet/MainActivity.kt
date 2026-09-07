package org.hashkinetics.wallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.hashkinetics.wallet.core.NoteView

/**
 * WA2 v0.1 — one Activity, one scrolling screen, the desktop wallet's journey top to bottom:
 * Setup (create / restore) → Unlock → Balance + faucet + send → Shielded (address, scan, notes,
 * shield / unshield / pay / disclose) → Backup (seed, passphrase, device lock) → Activity log.
 * Every button hands one call to the ViewModel; nothing here touches the core directly.
 */
class MainActivity : ComponentActivity() {
    private val vm: WalletVm by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { WalletScreen(vm) } }
    }
}

@Composable
fun WalletScreen(vm: WalletVm) {
    val ctx = LocalContext.current
    val st = vm.state
    Scaffold { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("HashKinetics Wallet", style = MaterialTheme.typography.headlineSmall)
            Text("testnet-1 · app 0.1.0 · core ${vm.coreVersion} · unaudited test software, nothing here is for sale", fontSize = 12.sp, color = Color.Gray)
            vm.busy?.let { Row { CircularProgressIndicator(Modifier.width(18.dp).height(18.dp)); Spacer(Modifier.width(8.dp)); Text(it) } }
            vm.error?.let { Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(12.dp)) { Text(it, color = MaterialTheme.colorScheme.error); TextButton(onClick = { vm.clearError() }) { Text("dismiss") } } } }

            when {
                st == null -> Text("…")
                !st.exists -> SetupSection(vm)
                st.locked -> UnlockSection(vm, st.needsKeyfile)
                else -> {
                    BalanceSection(vm)
                    ShieldedSection(vm)
                    BackupSection(vm)
                }
            }
            ActivitySection(vm) { url -> ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun Mono(text: String) = SelectionContainer { Text(text, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }

@Composable
fun SetupSection(vm: WalletVm) {
    var seed by remember { mutableStateOf("") }
    Section("No wallet on this phone yet") {
        Text("Keys are born on this device and never leave it. Create a fresh keychain, or restore one from its 32-byte seed (64 hex characters).")
        Button(onClick = { vm.create() }, enabled = vm.busy == null) { Text("Create keychain") }
        Divider()
        OutlinedTextField(seed, { seed = it }, label = { Text("Seed (64 hex) to restore") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedButton(onClick = { vm.restore(seed) }, enabled = vm.busy == null && seed.trim().length == 64) { Text("Restore") }
    }
}

@Composable
fun UnlockSection(vm: WalletVm, needsKeyfile: Boolean) {
    var pass by remember { mutableStateOf("") }
    Section("Unlock") {
        Text(if (needsKeyfile) "This wallet is sealed with a passphrase and this device's key file." else "This wallet is sealed with a passphrase (Argon2id, once per session).")
        OutlinedTextField(pass, { pass = it }, label = { Text("Passphrase") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button(onClick = { vm.unlock(pass); pass = "" }, enabled = vm.busy == null && pass.isNotEmpty()) { Text("Unlock") }
    }
}

@Composable
fun BalanceSection(vm: WalletVm) {
    val s = vm.status
    var to by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    Section("Balance") {
        vm.state?.accountId?.let { Text("Account id (share this to receive)"); Mono(it) }
        if (s == null) {
            Text("Tap Refresh to read the chain.")
        } else {
            Text(if (s.onChain) "${vm.formatMicro(s.balanceMicro)}  (fee ${vm.formatMicro(s.feeMicro)} per tx · max sendable ${vm.formatMicro(s.maxSendableMicro)})" else "Not on-chain yet — get test funds to be created + funded.", style = MaterialTheme.typography.titleLarge)
            Text("${s.chainId} · height ${s.height} · node ${s.nodeVersion}", fontSize = 12.sp, color = Color.Gray)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { vm.refresh() }, enabled = vm.busy == null) { Text("Refresh") }
            OutlinedButton(onClick = { vm.faucet() }, enabled = vm.busy == null) { Text("Get test funds") }
        }
        Divider()
        Text("Send (transparent)", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(to, { to = it }, label = { Text("To — account id (64 hex)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(amount, { amount = it }, label = { Text("Amount (e.g. 0.25)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button(onClick = { vm.send(to, amount) }, enabled = vm.busy == null && to.trim().length == 64 && amount.isNotBlank()) { Text("Send") }
    }
}

@Composable
fun ShieldedSection(vm: WalletVm) {
    val sc = vm.scan
    var amount by remember { mutableStateOf("") }
    var payTo by remember { mutableStateOf("") }
    var payAmount by remember { mutableStateOf("") }
    var memo by remember { mutableStateOf("") }
    var discloseCm by remember { mutableStateOf("") }
    Section("Shielded") {
        Text("Balances and counterparties in the pool are invisible on-chain; the fee is paid from the transparent balance. Proofs are made on the prover — a shielded operation takes a minute or two.", fontSize = 12.sp, color = Color.Gray)
        Button(onClick = { vm.scanPool() }, enabled = vm.busy == null) { Text(if (sc == null) "Scan the pool" else "Rescan") }
        if (sc != null) {
            Text("Your stealth address (share to receive shielded)"); Mono(sc.stealthAddress)
            Text("${sc.unspent} unspent note(s) · pool size ${sc.poolSize} · one-time spends used ${sc.otsUsed}/${sc.otsCapacity}", fontSize = 12.sp, color = Color.Gray)
            vm.notes.forEach { n -> NoteRow(vm, n) }
        }
        Divider()
        OutlinedTextField(amount, { amount = it }, label = { Text("Amount to shield / unshield") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { vm.shield(amount) }, enabled = vm.busy == null && amount.isNotBlank()) { Text("Shield") }
            OutlinedButton(onClick = { vm.unshield(amount) }, enabled = vm.busy == null && amount.isNotBlank()) { Text("Unshield") }
        }
        Divider()
        Text("Pay shielded", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(payTo, { payTo = it }, label = { Text("To — hkaddr:…") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(payAmount, { payAmount = it }, label = { Text("Amount") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(memo, { memo = it }, label = { Text("Memo (sealed to the recipient)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button(onClick = { vm.payShielded(payTo, payAmount, memo) }, enabled = vm.busy == null && payTo.startsWith("hkaddr:") && payAmount.isNotBlank()) { Text("Pay shielded") }
        Divider()
        Text("Disclose one received payment (auditor package)", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(discloseCm, { discloseCm = it }, label = { Text("Commitment (64 hex)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedButton(onClick = { vm.disclose(discloseCm) }, enabled = vm.busy == null && discloseCm.trim().length == 64) { Text("Build package") }
        vm.lastDisclosure?.let { Text("Package (also saved next to the wallet files):", fontSize = 12.sp); Mono(it.take(600) + if (it.length > 600) "…" else "") }
    }
}

@Composable
private fun NoteRow(vm: WalletVm, n: NoteView) {
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("${vm.formatMicro(n.valueMicro)}  ${if (n.spent) "spent" else "unspent"}  leaf ${n.leafIndex}${if (n.memo.isNotEmpty()) "  “${n.memo}”" else ""}", fontSize = 13.sp)
        Mono(n.commitment)
    }
}

@Composable
fun BackupSection(vm: WalletVm) {
    var pass by remember { mutableStateOf("") }
    val st = vm.state
    Section("Backup & protection") {
        Text("The seed restores the transparent account anywhere; shield.json (in this app's files) is the shielded side and must be backed up as a file — it cannot be re-derived. Write the seed down; never screenshot it.", fontSize = 12.sp, color = Color.Gray)
        if (vm.seedShown == null) OutlinedButton(onClick = { vm.showSeed() }, enabled = vm.busy == null) { Text("Show seed") }
        else { Mono(vm.seedShown!!); TextButton(onClick = { vm.hideSeed() }) { Text("hide") } }
        Divider()
        Text(if (st?.sealed == true) "Files are sealed on disk (HKE1, Argon2id 256 MiB)." else "Files are PLAIN on disk — set a passphrase.", fontSize = 12.sp)
        OutlinedTextField(pass, { pass = it }, label = { Text(if (st?.protected == true) "New passphrase" else "Passphrase (≥ 12 chars or 4+ words)") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { vm.protect(pass); pass = "" }, enabled = vm.busy == null && pass.isNotEmpty()) { Text(if (st?.protected == true) "Change" else "Protect") }
            OutlinedButton(onClick = { pass = vm.generatePassphrase() }, enabled = vm.busy == null) { Text("Generate 7 words") }
            if (st?.protected == true) TextButton(onClick = { vm.unprotect() }, enabled = vm.busy == null) { Text("Remove") }
            if (st?.protected == true) TextButton(onClick = { vm.lock() }, enabled = vm.busy == null) { Text("Lock") }
        }
        Divider()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Switch(checked = vm.deviceLock, onCheckedChange = { vm.setDeviceLock(it) }, enabled = vm.busy == null)
            Column {
                Text("Device lock (key file in the Android Keystore)", fontSize = 13.sp)
                Text("On: the sealed files need this device too — export the key file before restoring elsewhere. Re-protect after switching.", fontSize = 11.sp, color = Color.Gray)
            }
        }
        if (vm.deviceLock) vm.exportKeyfileHex()?.let { Text("Key file (HK_WALLET_KEYFILE on a PC):", fontSize = 12.sp); Mono(it) }
    }
}

@Composable
fun ActivitySection(vm: WalletVm, open: (String) -> Unit) {
    Section("Activity") {
        if (vm.log.isEmpty()) Text("—", color = Color.Gray)
        vm.log.take(60).forEach { l ->
            val color = when (l.level) { "ok" -> Color(0xFF2E7D32); "error" -> MaterialTheme.colorScheme.error; else -> Color.DarkGray }
            Row(Modifier.fillMaxWidth()) {
                Text("${l.time}  ", fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = Color.Gray)
                Column {
                    Text(l.text, fontSize = 12.sp, color = color)
                    l.link?.let { TextButton(onClick = { open(it) }) { Text("open in explorer", fontSize = 11.sp) } }
                }
            }
        }
    }
}
