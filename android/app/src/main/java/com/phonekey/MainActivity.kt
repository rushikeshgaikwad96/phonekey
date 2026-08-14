package com.phonekey

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.phonekey.crypto.KeyManager
import com.phonekey.engine.UnlockController

class MainActivity : FragmentActivity() {

    private lateinit var keyManager: KeyManager
    private var unlockController: UnlockController? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keyManager = KeyManager()

        if (!keyManager.isKeyPresent()) {
            keyManager.generateKey()
        }

        val deviceId = ByteArray(16) { 0x11.toByte() }
        unlockController = UnlockController(this, deviceId, keyManager)

        setContent {
            PhoneKeyAppUI(
                onGenerateKey = {
                    val meta = keyManager.generateKey()
                    Toast.makeText(this, "Key Generated! StrongBox: ${meta.isStrongBoxBacked}", Toast.LENGTH_SHORT).show()
                },
                onConnectTarget = { host, port ->
                    unlockController?.startConnection(host, port)
                }
            )
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unlockController?.stop()
    }
}

@Composable
fun PhoneKeyAppUI(
    onGenerateKey: () -> Unit,
    onConnectTarget: (String, Int) -> Unit
) {
    var host by remember { mutableStateOf("192.168.1.50") }
    var portText by remember { mutableStateOf("8443") }
    var statusText by remember { mutableStateOf("Ready to authenticate") }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "PhoneKey Biometric Unlock",
                style = MaterialTheme.typography.headlineMedium
            )

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("Windows Host IP / Name") }
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it },
                label = { Text("Agent Port") }
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    val port = portText.toIntOrNull() ?: 8443
                    statusText = "Connecting..."
                    onConnectTarget(host, port)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Connect & Authorize Windows PC")
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = onGenerateKey,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Re-generate Keystore Key")
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Status: $statusText",
                style = MaterialTheme.typography.bodyLarge
            )
        }
    }
}
