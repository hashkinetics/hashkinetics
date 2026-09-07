package org.hashkinetics.wallet

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The core's key-file second factor, kept on the device: 32 random bytes (from the core's
 * `newKeyfile()`), encrypted with an AES-256-GCM key that lives in the Android Keystore and
 * never leaves the secure hardware. `filesDir/keyfile.bin` = 12-byte IV ‖ ciphertext.
 *
 * What this buys: a copy of the wallet files (a cloud backup, a lost phone's storage image) is
 * useless without BOTH the passphrase and this device — the envelope names the key file, the
 * core refuses to even run the KDF without it. What it costs: restoring on a PC needs the
 * exported key file too (Backup screen → `HK_WALLET_KEYFILE`). Off by default for that reason.
 *
 * v0.1: no user-authentication requirement on the Keystore key (biometric release is WA2.1 —
 * `setUserAuthenticationRequired(true)` + BiometricPrompt around `load()`).
 */
class DeviceKeyfile(ctx: Context) {
    private val file = File(ctx.filesDir, "keyfile.bin")
    private val alias = "hk-wallet-keyfile-wrap"

    fun exists(): Boolean = file.exists()

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun store(bytes: ByteArray) {
        require(bytes.size == 32) { "key file must be 32 bytes" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(bytes)
        file.writeBytes(c.iv + ct)
    }

    fun load(): ByteArray? {
        if (!file.exists()) return null
        return try {
            val blob = file.readBytes()
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            c.doFinal(blob.copyOfRange(12, blob.size))
        } catch (e: Exception) {
            null // a wiped Keystore (factory reset, new device) cannot open it: the user restores with the exported copy
        }
    }

    fun clear() {
        file.delete()
    }
}
