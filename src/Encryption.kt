
import java.io.File
import java.nio.charset.Charset
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

fun main() {
    val text = File("src/data.json").readText(Charsets.UTF_8)
    val map = encrypt(text.toByteArray(), "badpassword".toCharArray())
    println(map["salt"]?.toString(Charset.defaultCharset()))
    println(map["iv"]?.toString(Charset.defaultCharset()))
    map["encrypted"]?.let { File("public/data.enc").writeBytes(it) }
    println("${map["encrypted"]}")
    val result = decrypt(map, "badpawssword".toCharArray())
    println("$result")
}

fun encrypt(
    dataToEncrypt: ByteArray,
    password: CharArray
): HashMap<String, ByteArray> {
    val map = HashMap<String, ByteArray>()

    try {
        // 1
        //Random salt for next step
        val salt = "nacllcan".toByteArray()
//        val random = SecureRandom()
//        val salt = ByteArray(8)
//        random.nextBytes(salt)

        // 2
        //PBKDF2 - derive the key from the password, don't use passwords directly
        val pbKeySpec = PBEKeySpec(password, salt, 1324, 256)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, "AES")

        // 3
        //Create initialization vector for AES
//        val ivRandom = SecureRandom() //not caching previous seeded instance of SecureRandom
//        val iv = ByteArray(16)
//        ivRandom.nextBytes(iv)
        val iv = "someIV12345abcde".toByteArray()
        val ivSpec = IvParameterSpec(iv)

        // 4
        //Encrypt
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        val encrypted = cipher.doFinal(dataToEncrypt)

        // 5
        map["salt"] = salt
        map["iv"] = iv
        map["encrypted"] = encrypted
    } catch (e: Exception) {
        println("encryption exception $e")
    }

    return map

}

fun decrypt(map: HashMap<String, ByteArray>, password: CharArray): ByteArray? {
    var decrypted: ByteArray? = null
    try {
        // 1
        val salt = map["salt"]
        val iv = map["iv"]
        val encrypted = map["encrypted"]

        // 2
        //regenerate key from password
        val pbKeySpec = PBEKeySpec(password, salt, 1324, 256)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, "AES")

        // 3
        //Decrypt
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        decrypted = cipher.doFinal(encrypted)
    } catch (e: Exception) {
        println("decryption exception $e")
    }

    return decrypted
}

fun keystoreEncrypt(dataToEncrypt: ByteArray): HashMap<String, ByteArray> {
    val map = HashMap<String, ByteArray>()
    try {

        // 1
        //Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry("MyKeyAlias", null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey

        // 2
        //Encrypt data
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
        // 1
        //Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry("MyKeyAlias", null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey

        // 2
        //Extract info from map
        val encryptedBytes = map["encrypted"]
        val ivBytes = map["iv"]

        // 3
        //Decrypt data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        decrypted = cipher.doFinal(encryptedBytes)
    } catch (e: Throwable) {
        e.printStackTrace()
    }

    return decrypted
}


