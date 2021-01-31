package crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex

import java.security.Security
import javax.crypto.{Cipher, KeyGenerator, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

object Symetric {
  Security.addProvider(new BouncyCastleProvider())
  val iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3")
  //create secret key from byte array
  def secretKey(key: Array[Byte]): SecretKey = {
    new SecretKeySpec(key, "AES")
  }

  def genSecretKey(): SecretKey = {
    val kGen = KeyGenerator.getInstance("AES", "BC")
    kGen.generateKey()
  }

  def ecbShortExample(input:Array[Byte], key:SecretKey) = {
    // Electronic code book
    val cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC")
    println("input    : " + Hex.toHexString(input))

    cipher.init(Cipher.ENCRYPT_MODE, key)
    val output = cipher.doFinal(input)
    println("encrypted: " + Hex.toHexString(output))

    cipher.init(Cipher.DECRYPT_MODE, key)
    println("decrypted: " + Hex.toHexString(cipher.doFinal(output)))
  }

  def cbcExample(input:Array[Byte], key:SecretKey) = {
    val cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC")
    println("input    : " + Hex.toHexString(input))
    // or cipher.getIV
    // or SecureRandom
    //IV initialization vector
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv))
    val output = cipher.doFinal(input)
    println("encrypted: " + Hex.toHexString(output))

    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv))
    println("decrypted: " + Hex.toHexString(cipher.doFinal(output)))
  }


  def cbcPadExample(input:Array[Byte], key: SecretKey)={

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC")
    System.out.println("input    : " + Hex.toHexString(input))

    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv))
    val output = cipher.doFinal(input)
    System.out.println("encrypted: " + Hex.toHexString(output))

    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv))
    val finalOutput = new Array[Byte](cipher.getOutputSize(output.length))
    var len = cipher.update(output, 0, output.length, finalOutput, 0)
    len += cipher.doFinal(finalOutput, len)
   // System.out.println("decrypted: " + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)))
  }
  
}

object Main {

  val keyBytes: Array[Byte] = Hex.decode("000102030405060708090a0b0c0d0e0f")
  val input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7" + "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7")
  val key = Symetric.secretKey(keyBytes)

  def main(args: Array[String]): Unit = {
    Symetric.ecbShortExample(input, key)
    Symetric.cbcExample(input, key)
    Symetric.cbcPadExample(input, key)
  }
}
