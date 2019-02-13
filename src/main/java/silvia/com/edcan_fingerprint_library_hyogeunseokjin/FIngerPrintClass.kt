@file:Suppress("DEPRECATION")

package silvia.com.edcan_fingerprint_library_hyogeunseokjin

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.Context.FINGERPRINT_SERVICE
import android.content.Context.KEYGUARD_SERVICE
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.app.ActivityCompat
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

/**
 * Created by Kinetic on 2019-02-14.
 */

// Declare a string variable for the key we’re going to use in our fingerprint authentication
private lateinit var cipher: Cipher
private lateinit var keyStore: KeyStore

class FIngerPrintClass {

    companion object {

        fun auth(context: Context, KEY_NAME: String): String {

            //Get an instance of KeyguardManager and FingerprintManager//
            val keyguardManager = context.getSystemService(KEYGUARD_SERVICE) as KeyguardManager
            val fingerprintManager = context.getSystemService(FINGERPRINT_SERVICE) as FingerprintManager

            //Check whether the device has a fingerprint sensor

            return when {
                !fingerprintManager.isHardwareDetected -> context.getString(R.string.error_fingerprint_not_supported)
                ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED -> context.getString(R.string.error_enable_fingerprint)
                !fingerprintManager.hasEnrolledFingerprints() -> context.getString(R.string.error_not_configured)
                !keyguardManager.isKeyguardSecure -> context.getString(R.string.error_enable_lockscreen)
                else -> {
                    try {
                        generateKey(KEY_NAME)
                    } catch (e: FingerprintException) {
                        e.printStackTrace()
                    }

                    if (initCipher(KEY_NAME)) {
                        val cryptoObject = FingerprintManager.CryptoObject(cipher)
                        val helper = FingerprintHandler(context)

                        helper.startAuth(fingerprintManager, cryptoObject)
                    }
                    ""
                }
            }
        }

        @Throws(FingerprintException::class)
        fun generateKey(KEY_NAME: String) {
            try {
                // Obtain a reference to the Keystore using the standard Android keystore container identifier (“AndroidKeystore”)//
                keyStore = KeyStore.getInstance("AndroidKeyStore")

                //Generate the key//
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

                //Initialize an empty KeyStore//
                keyStore.load(null)

                //Initialize the KeyGenerator//
                keyGenerator.init(
                        //Specify the operation(s) this key can be used for//
                        KeyGenParameterSpec.Builder(KEY_NAME,
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
                                .setUserAuthenticationRequired(true)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                .build())

                //Generate the key//
                keyGenerator.generateKey()

            } catch (exc: KeyStoreException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            } catch (exc: NoSuchAlgorithmException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            } catch (exc: NoSuchProviderException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            } catch (exc: InvalidAlgorithmParameterException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            } catch (exc: CertificateException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            } catch (exc: IOException) {
                exc.printStackTrace()
                throw FingerprintException(exc)
            }
        }

        private fun initCipher(KEY_NAME: String): Boolean {
            try {
                //Obtain a cipher instance and configure it with the properties required for fingerprint authentication//
                cipher = Cipher.getInstance(
                        "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Failed to get Cipher", e)
            } catch (e: NoSuchPaddingException) {
                throw RuntimeException("Failed to get Cipher", e)
            }

            try {
                keyStore.load(null)
                val key = keyStore.getKey(KEY_NAME, null) as SecretKey
                cipher.init(Cipher.ENCRYPT_MODE, key)
                //Return true if the cipher has been initialized successfully//
                return true

            } catch (e: KeyPermanentlyInvalidatedException) {
                //Return false if cipher initialization failed//
                return false
            } catch (e: KeyStoreException) {
                throw RuntimeException("Failed to init Cipher", e)
            } catch (e: CertificateException) {
                throw RuntimeException("Failed to init Cipher", e)
            } catch (e: UnrecoverableKeyException) {
                throw RuntimeException("Failed to init Cipher", e)
            } catch (e: IOException) {
                throw RuntimeException("Failed to init Cipher", e)
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Failed to init Cipher", e)
            } catch (e: InvalidKeyException) {
                throw RuntimeException("Failed to init Cipher", e)
            }
        }

        private class FingerprintException(e: Exception) : Exception(e)
    }

}