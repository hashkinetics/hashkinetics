package org.hashkinetics.wallet.ui

import android.graphics.Bitmap
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

/*
 * The HashKinetics engineering-dark design system, as on the site (vercel/app/globals.css), the deck and the
 * desktop wallet: near-black ground, navy panels, cyan for actions, violet for the shielded side, gold for
 * warnings, one monospace for anything that is bytes (ids, addresses, amounts). No external fonts.
 */
val Bg = Color(0xFF06080F)
val Bg2 = Color(0xFF090D19)
val Surface1 = Color(0xFF0F1730)
val Surface2 = Color(0xFF141D3A)
val Ink = Color(0xFFE7EAF6)
val Muted = Color(0xFF949CC0)
val Faint = Color(0xFF5C6690)
val Cyan = Color(0xFF4EF0D0)
val Violet = Color(0xFF8B7BFF)
val Gold = Color(0xFFF5C518)
val Danger = Color(0xFFFF5D7A)
val Ok = Color(0xFF43E08C)
val Line = Color(0xFF26305A)

val PanelShape = RoundedCornerShape(14.dp)
val ControlShape = RoundedCornerShape(10.dp)

private val HkScheme = darkColorScheme(
    primary = Cyan, onPrimary = Bg, primaryContainer = Surface2, onPrimaryContainer = Cyan, inversePrimary = Cyan,
    secondary = Violet, onSecondary = Bg, secondaryContainer = Surface2, onSecondaryContainer = Ink,
    tertiary = Gold, onTertiary = Bg, tertiaryContainer = Surface2, onTertiaryContainer = Gold,
    background = Bg, onBackground = Ink,
    surface = Surface1, onSurface = Ink, surfaceVariant = Surface2, onSurfaceVariant = Muted, surfaceTint = Cyan,
    surfaceBright = Surface2, surfaceDim = Bg, surfaceContainerLowest = Bg, surfaceContainerLow = Bg2,
    surfaceContainer = Surface1, surfaceContainerHigh = Surface2, surfaceContainerHighest = Surface2,
    inverseSurface = Ink, inverseOnSurface = Bg,
    error = Danger, onError = Bg, errorContainer = Color(0xFF3A1622), onErrorContainer = Danger,
    outline = Line, outlineVariant = Line, scrim = Color.Black,
)

@Composable
fun HkTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = HkScheme, content = content)

// ---- building blocks -------------------------------------------------------------------------------

/** HASH·KINETICS, tracked like the site's wordmark. */
@Composable
fun Wordmark(size: TextUnit = 13.5.sp) {
    Text(
        buildAnnotatedString { append("HASH"); withStyle(SpanStyle(color = Cyan)) { append("KINETICS") } },
        color = Ink, fontSize = size, fontWeight = FontWeight.ExtraBold, letterSpacing = 0.24.em,
    )
}

/** Small uppercase label above a block (the site's `.kicker`). */
@Composable
fun Kicker(text: String, color: Color = Cyan) {
    Text(text.uppercase(), color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.22.em)
}

/** Outlined pill, e.g. TESTNET. */
@Composable
fun Pill(text: String, color: Color = Cyan) {
    Text(
        text, color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.18.em,
        modifier = Modifier.border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(999.dp)).padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

/** A navy panel with a hairline, optionally titled by a kicker. Every card on every screen is one of these. */
@Composable
fun Panel(kicker: String? = null, accent: Color = Cyan, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().background(Surface1, PanelShape).border(1.dp, Line, PanelShape).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (kicker != null) Kicker(kicker, accent)
        content()
    }
}

/** Bytes on screen: ids, addresses, packages — selectable, monospace. */
@Composable
fun Mono(text: String, color: Color = Ink, size: TextUnit = 12.sp) {
    SelectionContainer { Text(text, color = color, fontFamily = FontFamily.Monospace, fontSize = size, lineHeight = (size.value * 1.45f).sp) }
}

@Composable
fun Hint(text: String, color: Color = Muted) = Text(text, color = color, fontSize = 12.sp, lineHeight = 17.sp)

@Composable
fun Field(value: String, onChange: (String) -> Unit, label: String, password: Boolean = false, mono: Boolean = false) {
    OutlinedTextField(
        value, onChange, label = { Text(label) }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
        textStyle = if (mono) LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp) else LocalTextStyle.current,
        shape = ControlShape,
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Cyan, unfocusedBorderColor = Line, focusedLabelColor = Cyan, unfocusedLabelColor = Muted,
            cursorColor = Cyan, focusedTextColor = Ink, unfocusedTextColor = Ink,
        ),
    )
}

/** Cyan fill, dark text — the desktop wallet's action button. */
@Composable
fun PrimaryButton(text: String, enabled: Boolean = true, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(
        onClick, modifier, enabled, shape = ControlShape,
        colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Bg, disabledContainerColor = Surface2, disabledContentColor = Faint),
    ) { Text(text, fontWeight = FontWeight.Bold) }
}

/** Outlined, coloured text — secondary actions. */
@Composable
fun GhostButton(text: String, enabled: Boolean = true, modifier: Modifier = Modifier, color: Color = Cyan, onClick: () -> Unit) {
    OutlinedButton(
        onClick, modifier, enabled, shape = ControlShape,
        border = BorderStroke(1.dp, if (enabled) color.copy(alpha = 0.6f) else Line),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = color, disabledContentColor = Faint),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

/** A caption on the left, Copy on the right. */
@Composable
fun CopyRow(caption: String, value: String) {
    val clip = LocalClipboardManager.current
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(caption, color = Faint, fontSize = 11.sp, modifier = Modifier.weight(1f))
        TextButton(onClick = { clip.setText(AnnotatedString(value)) }) { Text("Copy", color = Cyan) }
    }
}

// ---- QR ----------------------------------------------------------------------------------------------

private val QR_DARK: Int = 0xFF06080F.toInt()
private val QR_LIGHT: Int = 0xFFE7EAF6.toInt()

/** One pixel per module; the Image scales it with no filtering so the modules stay square. */
fun qrBitmap(text: String): ImageBitmap? = try {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 0))
    val w = m.width
    val h = m.height
    val px = IntArray(w * h) { i -> if (m.get(i % w, i / w)) QR_DARK else QR_LIGHT }
    Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888).asImageBitmap()
} catch (e: Exception) {
    null
}

@Composable
fun Qr(text: String, size: Dp = 176.dp) {
    val bmp = remember(text) { qrBitmap(text) }
    if (bmp != null) {
        Box(Modifier.background(Ink, RoundedCornerShape(10.dp)).padding(10.dp)) {
            Image(bmp, contentDescription = null, modifier = Modifier.size(size), filterQuality = FilterQuality.None)
        }
    }
}
