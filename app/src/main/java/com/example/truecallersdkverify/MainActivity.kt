package com.example.truecallersdkverify

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.truecaller.android.sdk.oAuth.TcOAuthCallback
import com.truecaller.android.sdk.oAuth.TcOAuthData
import com.truecaller.android.sdk.oAuth.TcOAuthError
import com.truecaller.android.sdk.oAuth.TcSdk
import com.truecaller.android.sdk.oAuth.TcSdkOptions
import java.math.BigInteger
import java.security.SecureRandom

class MainActivity : AppCompatActivity() {

    private lateinit var stateRequested: String
    private lateinit var codeVerifier: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Generate OAuth state
        stateRequested = BigInteger(130, SecureRandom()).toString(32)

        // Initialize Truecaller SDK
        val tcSdkOptions = TcSdkOptions.Builder(this, tcOAuthCallback)
            .buttonColor(Color.GREEN)
            .buttonTextColor(Color.WHITE)
            .buttonShapeOptions(TcSdkOptions.BUTTON_SHAPE_ROUNDED)
            .footerType(TcSdkOptions.FOOTER_TYPE_SKIP)
            .sdkOptions(TcSdkOptions.OPTION_VERIFY_ONLY_TC_USERS)
            .ctaText(TcSdkOptions.CTA_TEXT_CONTINUE)
            .build()

        TcSdk.init(tcSdkOptions)

        // Set OAuth state
        TcSdk.getInstance().setOAuthState(stateRequested)

        // Set OAuth scopes
        TcSdk.getInstance().setOAuthScopes(arrayOf("profile", "phone", "openid"))

        // Generate PKCE code verifier and challenge
        codeVerifier = CodeVerifierUtil.generateRandomCodeVerifier()
        val codeChallenge = CodeVerifierUtil.getCodeChallenge(codeVerifier)
        codeChallenge?.let {
            TcSdk.getInstance().setCodeChallenge(it)
        } ?: run {
            Toast.makeText(this, "Code challenge generation failed", Toast.LENGTH_SHORT).show()
        }
    }

    // Verify button click
    fun verify(view: View) {
        // Ensure OAuth flow is usable before attempting
        if (TcSdk.getInstance().isOAuthFlowUsable) {
            TcSdk.getInstance().getAuthorizationCode(this)
        } else {
            Toast.makeText(this, "Truecaller OAuth flow is not usable", Toast.LENGTH_SHORT).show()
        }
    }

    private val tcOAuthCallback = object : TcOAuthCallback {
        override fun onSuccess(tcOAuthData: TcOAuthData) {
            Toast.makeText(
                this@MainActivity,
                "Authentication Successful: ${tcOAuthData}",
                Toast.LENGTH_SHORT
            ).show()

            // Navigate to next activity after success
            val intent = Intent(this@MainActivity, HomeActivity::class.java)
            startActivity(intent)
            finish()
        }

        override fun onVerificationRequired(tcOAuthError: TcOAuthError?) {
            Toast.makeText(this@MainActivity, "Verification required.", Toast.LENGTH_SHORT).show()
        }

        override fun onFailure(tcOAuthError: TcOAuthError) {
            // Extract the error details properly
            val errorMessage = tcOAuthError.errorMessage ?: "Unknown error"
            Toast.makeText(
                this@MainActivity,
                "Authentication Failed: $errorMessage",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == TcSdk.SHARE_PROFILE_REQUEST_CODE) {
            TcSdk.getInstance().onActivityResultObtained(this, requestCode, resultCode, data)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        TcSdk.clear()
    }

    object CodeVerifierUtil {
        fun generateRandomCodeVerifier(): String {
            val secureRandom = SecureRandom()
            val codeVerifier = ByteArray(32)
            secureRandom.nextBytes(codeVerifier)
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier)
        }

        fun getCodeChallenge(codeVerifier: String): String? {
            return try {
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(codeVerifier.toByteArray())
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
            } catch (e: Exception) {
                null
            }
        }
    }
}
