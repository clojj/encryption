import java.io.File
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

fun main() {
    val text = File("src/data.json").readText(Charsets.UTF_8)

    val encryptedText = encrypt(text.toByteArray(), "badpassword".toCharArray())

    File("public/data.enc").writeBytes(encryptedText)

    val decryptedText = decrypt(encryptedText, "badpassword".toCharArray())
    val decryptedTextStr = decryptedText?.let { String(it) }
    println("$decryptedTextStr")
}

// TODO random salt
//        val random = SecureRandom()
//        val salt = ByteArray(8)
//        random.nextBytes(salt)

val salt = "nacllcan".toByteArray()


// TODO random initialization vector für AES
//        val ivRandom = SecureRandom() //not caching previous seeded instance of SecureRandom
//        val iv = ByteArray(16)
//        ivRandom.nextBytes(iv)

val iv = "someIV12345abcde".toByteArray()

const val secretKeyFactoryInstance = "PBKDF2WithHmacSHA256"
const val numberOfIterations = 1324
const val keySize = 256

const val cipherInstance = "AES/CBC/PKCS5Padding"


var keySpec: SecretKeySpec? = null

fun encrypt(
    dataToEncrypt: ByteArray,
    password: CharArray
): ByteArray {

    try {
        // PBKDF2 - mit password den key erzeugen
        val pbKeySpec = PBEKeySpec(password, salt, numberOfIterations, keySize)
        val secretKeyFactory = SecretKeyFactory.getInstance(secretKeyFactoryInstance)
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        keySpec = SecretKeySpec(keyBytes, "AES")

        val ivSpec = IvParameterSpec(iv)

        // Encryption
        val cipher = Cipher.getInstance(cipherInstance)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        val encrypted = cipher.doFinal(dataToEncrypt)
        return encrypted

    } catch (e: Exception) {
        println("encryption exception $e")
        throw e
    }
}

fun decrypt(
    encrypted: ByteArray,
    password: CharArray
): ByteArray? {
    try {
        // PBKDF2 - mit password den key erzeugen
        val pbKeySpec = PBEKeySpec(password, salt, numberOfIterations, keySize)
        val secretKeyFactory = SecretKeyFactory.getInstance(secretKeyFactoryInstance)
        val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, "AES")

        val ivSpec = IvParameterSpec(iv)

        // Decryption
        val cipher = Cipher.getInstance(cipherInstance)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        val decrypted = cipher.doFinal(encrypted)
        return decrypted

    } catch (e: Exception) {
        println("decryption exception $e")
        throw e
    }
}

