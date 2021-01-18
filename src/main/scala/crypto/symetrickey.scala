package crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex

import java.security.Security
import javax.crypto.{KeyGenerator, SecretKey}
import javax.crypto.spec.SecretKeySpec

object Symetric {
  Security.addProvider(new BouncyCastleProvider())
  //create secret key from byte array
  def secretKey():SecretKey = {
    val keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f")
    new SecretKeySpec(keyBytes, "AES")
  }
  def genSecretKey():SecretKey = {
    val kGen = KeyGenerator.getInstance("AES", "BC")
    kGen.generateKey()
  }
}
object Main {

  def main(args: Array[String]): Unit = {
    println(Symetric.genSecretKey())
  }
}
