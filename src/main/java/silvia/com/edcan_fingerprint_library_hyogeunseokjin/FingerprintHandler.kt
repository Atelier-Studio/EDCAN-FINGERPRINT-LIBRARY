@file:Suppress("DEPRECATION")

package silvia.com.edcan_fingerprint_library_hyogeunseokjin


import android.Manifest
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.widget.Toast
import android.content.pm.PackageManager
import android.os.Build
import android.os.CancellationSignal
import android.support.annotation.RequiresApi
import android.support.v4.app.ActivityCompat


@RequiresApi(Build.VERSION_CODES.M)
class FingerprintHandler(mContext: Context) : FingerprintManager.AuthenticationCallback() {

    private val context = mContext

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        super.onAuthenticationError(errorCode, errString)
        Toast.makeText(context, errString, Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        super.onAuthenticationSucceeded(result)
        Toast.makeText(context, "Success", Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        super.onAuthenticationHelp(helpCode, helpString)
        Toast.makeText(context, helpString, Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
        Toast.makeText(context, "Authentication Failed", Toast.LENGTH_LONG).show()
    }

    fun startAuth(manager: FingerprintManager, cryptoObject: FingerprintManager.CryptoObject) {
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        manager.authenticate(cryptoObject, CancellationSignal(), 0, this, null)
    }
}