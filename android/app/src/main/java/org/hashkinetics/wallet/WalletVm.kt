package org.hashkinetics.wallet

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.hashkinetics.wallet.core.Endpoints
import org.hashkinetics.wallet.core.NoteView
import org.hashkinetics.wallet.core.Progress
import org.hashkinetics.wallet.core.ScanResult
import org.hashkinetics.wallet.core.Status
import org.hashkinetics.wallet.core.TxResult
import org.hashkinetics.wallet.core.Wallet
import org.hashkinetics.wallet.core.WalletException
import org.hashkinetics.wallet.core.WalletState
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One line of the ACTIVITY panel — what the core reports while it works. */
data class LogLine(val time: String, val level: String, val text: String, val link: String?)

/**
 * The app's only state holder. Every core call is blocking and runs on the IO dispatcher under
 * one mutex (the core keeps its counters on disk — one operation at a time, in order); the
 * screen only ever reads the fields below.
 */
class WalletVm(app: Application) : AndroidViewModel(app) {
    private val dir: File = File(app.filesDir, "wallet").apply { mkdirs() }
    private val keyfile = DeviceKeyfile(app)
    private val calls = Mutex()

    private val wallet: Wallet = Wallet(dir.absolutePath, Endpoints(
        rpc = BuildConfigDefaults.RPC,
        faucet = BuildConfigDefaults.FAUCET,
        prover = BuildConfigDefaults.PROVER,
        explorer = BuildConfigDefaults.EXPLORER,
    )).also { w ->
        w.setMobileKdf(true)
        w.setListener(object : Progress {
            override fun onLog(level: String, line: String, link: String?) {
                pushLog(level, line, link)
            }
        })
        keyfile.load()?.let { w.setKeyfile(it) }
    }

    // ---- observable state ----
    var state by mutableStateOf<WalletState?>(null); private set
    var status by mutableStateOf<Status?>(null); private set
    var scan by mutableStateOf<ScanResult?>(null); private set
    var notes by mutableStateOf<List<NoteView>>(emptyList()); private set
    var busy by mutableStateOf<String?>(null); private set
    var error by mutableStateOf<String?>(null); private set
    var seedShown by mutableStateOf<String?>(null); private set
    var lastDisclosure by mutableStateOf<String?>(null); private set
    var deviceLock by mutableStateOf(keyfile.exists()); private set
    val log = mutableStateListOf<LogLine>()
    val coreVersion: String get() = wallet.coreVersion()

    init { refreshState() }

    private fun pushLog(level: String, line: String, link: String?) {
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        viewModelScope.launch(Dispatchers.Main) {
            log.add(0, LogLine(t, level, line, link))
            while (log.size > 200) log.removeAt(log.size - 1)
        }
    }

    /** Run one core call off the main thread; errors land in [error], never crash the app. */
    private fun run(label: String, block: suspend () -> Unit) {
        viewModelScope.launch {
            calls.withLock {
                busy = label; error = null
                try {
                    withContext(Dispatchers.IO) { block() }
                } catch (e: WalletException) {
                    // the generated exception renders as "msg=…"; show the core's sentence itself
                    error = (e as? WalletException.Message)?.msg ?: e.message ?: e.toString()
                    pushLog("error", error ?: "error", null)
                } catch (e: Throwable) {
                    error = e.toString()
                    pushLog("error", error ?: "error", null)
                } finally {
                    busy = null
                    state = wallet.state()
                }
            }
        }
    }

    fun refreshState() = run("state") { state = wallet.state() }
    fun clearError() { error = null }

    // ---- setup / unlock ----
    fun create() = run("creating keychain") { wallet.create(); state = wallet.state(); refreshNow() }
    fun restore(seedHex: String) = run("restoring keychain") { wallet.restore(seedHex.trim()); state = wallet.state(); refreshNow() }
    fun unlock(passphrase: String) = run("unlocking") { wallet.unlock(passphrase); state = wallet.state(); refreshNow() }
    fun lock() = run("locking") { wallet.lock(); status = null; scan = null; notes = emptyList(); seedShown = null }

    /** Set (or change) the passphrase — files re-written sealed, HKE1, phone-sized KDF. */
    fun protect(passphrase: String) = run("sealing files") {
        wallet.passphraseStrength(passphrase)
        wallet.protect(passphrase)
    }
    fun unprotect() = run("removing passphrase") { wallet.unprotect() }
    fun generatePassphrase(): String = wallet.generatePassphrase()

    /** Device-bound second factor: a 32-byte key file kept encrypted in the Android Keystore.
     *  Off by default so a phone backup restores on a PC with the passphrase alone; on, the
     *  files need this device (or the exported key file) as well. */
    fun setDeviceLock(on: Boolean) = run(if (on) "enabling device lock" else "disabling device lock") {
        if (on) {
            val bytes = keyfile.load() ?: wallet.newKeyfile().also { keyfile.store(it) }
            wallet.setKeyfile(bytes)
        } else {
            wallet.setKeyfile(null)
            keyfile.clear()
        }
        deviceLock = on
        // re-seal under the new factor if a passphrase is set: protect() rewrites both files
        // (the caller re-enters the passphrase on the screen; nothing is written here).
    }
    fun exportKeyfileHex(): String? = keyfile.load()?.joinToString("") { "%02x".format(it) }

    // ---- transparent ----
    private suspend fun refreshNow() {
        val st = wallet.state()
        state = st
        if (st.accountId != null) status = wallet.refresh()
    }
    fun refresh() = run("refreshing") { refreshNow() }
    fun faucet() = run("asking the faucet") { wallet.faucet(); refreshNow() }
    fun send(to: String, amountText: String) = run("sending") {
        val micro = wallet.parseAmount(amountText) ?: throw WalletException.Message("amount: use digits and up to 6 decimals")
        wallet.send(to.trim(), micro); refreshNow()
    }
    fun showSeed() = run("reading seed") { seedShown = wallet.exportSeed() }
    fun hideSeed() { seedShown = null }
    fun formatMicro(micro: ULong): String = wallet.formatAmount(micro)

    // ---- shielded ----
    fun scanPool() = run("scanning the pool") { scan = wallet.scan(); notes = scan!!.notes; refreshNow() }
    fun shield(amountText: String) = run("shielding (proving on the prover)") {
        val micro = wallet.parseAmount(amountText) ?: throw WalletException.Message("amount: use digits and up to 6 decimals")
        wallet.shield(micro); scan = wallet.scan(); notes = scan!!.notes; refreshNow()
    }
    fun unshield(amountText: String) = run("unshielding (proving on the prover)") {
        val micro = wallet.parseAmount(amountText) ?: throw WalletException.Message("amount: use digits and up to 6 decimals")
        wallet.unshield(micro); scan = wallet.scan(); notes = scan!!.notes; refreshNow()
    }
    fun payShielded(to: String, amountText: String, memo: String) = run("paying shielded (proving on the prover)") {
        val micro = wallet.parseAmount(amountText) ?: throw WalletException.Message("amount: use digits and up to 6 decimals")
        wallet.payShielded(to.trim(), micro, memo); scan = wallet.scan(); notes = scan!!.notes; refreshNow()
    }
    fun disclose(commitmentHex: String) = run("building the disclosure package") { lastDisclosure = wallet.disclose(commitmentHex.trim()) }
    fun explorerUrl(txid: String): String = wallet.explorerTxUrl(txid)
}

/** The public testnet-1 endpoints; a devnet build overrides these (Settings screen, WA2.1). */
object BuildConfigDefaults {
    const val RPC = "https://rpc.hashkinetics.org"
    const val FAUCET = "https://faucet.hashkinetics.org"
    const val PROVER = "https://prover.hashkinetics.org"
    const val EXPLORER = "https://www.hashkinetics.org/explorer/"
}
