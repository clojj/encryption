import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

fun keystoreEncrypt(dataToEncrypt: ByteArray): HashMap<String, ByteArray> {
    val map = HashMap<String, ByteArray>()
    try {

        // get key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry("MyKeyAlias", null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey

        // Encryption
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val ivBytes = cipher.iv
        val encryptedBytes = cipher.doFinal(dataToEncrypt)

        // 3
        map["iv"] = ivBytes
        map["encrypted"] = encryptedBytes
    } catch (e: Throwable) {
        e.printStackTrace()
    }

    return map
}

fun keystoreDecrypt(map: HashMap<String, ByteArray>): ByteArray? {
    var decrypted: ByteArray? = null
    try {
        // get key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry("MyKeyAlias", null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey

        // extract info from map
        val encryptedBytes = map["encrypted"]
        val ivBytes = map["iv"]

        // Decryption
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        decrypted = cipher.doFinal(encryptedBytes)
    } catch (e: Throwable) {
        e.printStackTrace()
    }

    return decrypted
}
