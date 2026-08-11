package com.vpn.client.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlin.coroutines.coroutineContext

/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628) client for the Datasee IdP.
 *
 * Flow:
 * 1. [startDeviceAuthorization] registers this device and returns a user code +
 *    verification URI. The caller opens [DeviceAuthorization.verificationUriComplete]
 *    in a browser (the IdP is public, so this works without the VPN).
 * 2. [pollForToken] polls the token endpoint until the user approves in the
 *    browser, then returns the OIDC id_token. Cancel the calling coroutine to
 *    abort the flow.
 */
class DeviceFlowClient {

    companion object {
        private const val DEVICE_AUTH_ENDPOINT = "https://auth.datasee.co.kr/oidc/device/auth"
        private const val TOKEN_ENDPOINT = "https://auth.datasee.co.kr/oidc/token"
        private const val CLIENT_ID = "opentunnel"
        private const val SCOPE = "openid email profile"
        private const val DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000
        private const val DEFAULT_INTERVAL_SEC = 5
        private const val SLOW_DOWN_BACKOFF_SEC = 5

        /**
         * Best-effort read of the `email` claim from an id_token (JWT), for
         * display only — the server is what actually validates the token.
         * Mirrors DeviceFlowService.email(fromIdToken:) on the Apple clients.
         */
        fun emailFromIdToken(idToken: String): String? {
            val parts = idToken.split(".")
            if (parts.size < 2) return null
            return try {
                val payload = android.util.Base64.decode(
                    parts[1],
                    android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or
                        android.util.Base64.NO_WRAP
                )
                val claims = Json { ignoreUnknownKeys = true }
                    .parseToJsonElement(String(payload, Charsets.UTF_8))
                    .let { it as? kotlinx.serialization.json.JsonObject } ?: return null
                (claims["email"] as? kotlinx.serialization.json.JsonPrimitive)
                    ?.content
                    ?.takeIf { it.isNotBlank() }
            } catch (e: Exception) {
                null
            }
        }
    }

    private val json = Json { ignoreUnknownKeys = true }

    class DeviceFlowException(message: String) : Exception(message)

    @Serializable
    data class DeviceAuthorization(
        @SerialName("device_code") val deviceCode: String,
        @SerialName("user_code") val userCode: String,
        @SerialName("verification_uri") val verificationUri: String,
        @SerialName("verification_uri_complete") val verificationUriComplete: String,
        @SerialName("expires_in") val expiresIn: Int,
        @SerialName("interval") val interval: Int = DEFAULT_INTERVAL_SEC
    )

    @Serializable
    private data class TokenResponse(
        @SerialName("id_token") val idToken: String? = null,
        @SerialName("error") val error: String? = null,
        @SerialName("error_description") val errorDescription: String? = null
    )

    /**
     * Step 1: request a device + user code pair from the IdP.
     */
    suspend fun startDeviceAuthorization(): DeviceAuthorization = withContext(Dispatchers.IO) {
        val body = formEncode(
            "client_id" to CLIENT_ID,
            "scope" to SCOPE
        )
        val response = postForm(DEVICE_AUTH_ENDPOINT, body)
        try {
            json.decodeFromString<DeviceAuthorization>(response)
        } catch (e: Exception) {
            throw DeviceFlowException("SSO 시작에 실패했습니다 (응답 해석 오류)")
        }
    }

    /**
     * Step 2: poll the token endpoint until the user approves (or the code
     * expires / access is denied). Returns the OIDC id_token on success.
     *
     * Honors the server-provided polling interval, backing off +5s on
     * slow_down as required by RFC 8628.
     */
    suspend fun pollForToken(authorization: DeviceAuthorization): String = withContext(Dispatchers.IO) {
        var intervalSec = maxOf(authorization.interval, 1)
        val deadline = System.currentTimeMillis() + authorization.expiresIn * 1000L
        val body = formEncode(
            "grant_type" to DEVICE_CODE_GRANT,
            "device_code" to authorization.deviceCode,
            "client_id" to CLIENT_ID
        )

        while (System.currentTimeMillis() < deadline) {
            delay(intervalSec * 1000L)
            coroutineContext.ensureActive()

            val response = postForm(TOKEN_ENDPOINT, body)
            val token = try {
                json.decodeFromString<TokenResponse>(response)
            } catch (e: Exception) {
                throw DeviceFlowException("SSO 응답을 해석하지 못했습니다")
            }

            when {
                token.idToken != null -> return@withContext token.idToken
                token.error == "authorization_pending" -> Unit // keep polling
                token.error == "slow_down" -> intervalSec += SLOW_DOWN_BACKOFF_SEC
                token.error == "expired_token" ->
                    throw DeviceFlowException("인증 코드가 만료되었습니다. 다시 시도해 주세요.")
                token.error == "access_denied" ->
                    throw DeviceFlowException("로그인이 거부되었습니다.")
                token.error != null ->
                    throw DeviceFlowException(token.errorDescription ?: "SSO 오류: ${token.error}")
                else ->
                    throw DeviceFlowException("SSO 응답에 토큰이 없습니다")
            }
        }
        throw DeviceFlowException("인증 코드가 만료되었습니다. 다시 시도해 주세요.")
    }

    /**
     * POST an x-www-form-urlencoded body and return the response body as text.
     * OAuth error responses come back with 4xx status but a JSON body, so the
     * error stream is read and returned for the caller to parse.
     */
    private fun postForm(endpoint: String, body: String): String {
        val connection = URL(endpoint).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.setRequestProperty("Accept", "application/json")
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val stream = if (connection.responseCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
                    ?: throw DeviceFlowException("SSO 서버 오류 (HTTP ${connection.responseCode})")
            }
            return stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }

    private fun formEncode(vararg params: Pair<String, String>): String {
        return params.joinToString("&") { (key, value) ->
            "${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
        }
    }
}
