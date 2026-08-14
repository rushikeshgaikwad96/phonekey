package com.phonekey.pairing

import org.json.JSONObject

data class QrPairingPayload(
    val protocolVersion: String,
    val sessionIdHex: String,
    val pcIdHex: String,
    val pcEcdhPubHex: String,
    val hostInfo: String
)

object QrPayloadParser {

    fun generateJson(payload: QrPairingPayload): String {
        val json = JSONObject()
        json.put("protocol_version", payload.protocolVersion)
        json.put("session_id", payload.sessionIdHex)
        json.put("pc_id", payload.pcIdHex)
        json.put("pc_ecdh_pub_hex", payload.pcEcdhPubHex)
        json.put("host_info", payload.hostInfo)
        return json.toString()
    }

    fun parseJson(jsonString: String): QrPairingPayload? {
        return try {
            val json = JSONObject(jsonString)
            QrPairingPayload(
                protocolVersion = json.getString("protocol_version"),
                sessionIdHex = json.getString("session_id"),
                pcIdHex = json.getString("pc_id"),
                pcEcdhPubHex = json.getString("pc_ecdh_pub_hex"),
                hostInfo = json.getString("host_info")
            )
        } catch (e: Exception) {
            null
        }
    }
}
