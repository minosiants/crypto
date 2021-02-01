package crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex

import java.security.{MessageDigest, Security}
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Mac, SecretKey}

object jsa {
  Security.addProvider(new BouncyCastleProvider())

  def computeDigest(digestName: String, data: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance(digestName, "BC")
    digest.update(data)
    digest.digest()
  }

  def computeMac(algorithm: String, key: SecretKey, data: Array[Byte]) = {

    val mac = Mac.getInstance(algorithm, "BC")
    mac.init(key)
    mac.update(data)
    mac.doFinal()

  }

  def digestExample() = {
    Hex.toHexString(computeDigest("SHA-1", "Hello World".getBytes))
  }

  def macExample() = {
    val key = new SecretKeySpec(
      Hex.decode("dfa66747de9ae63030ca32611497c827"),
      "AES")

    Hex.toHexString(computeMac("AESCMAC", key, "Hello World".getBytes))
  }

}

object ch3 {

  import jsa._

  def main(args: Array[String]): Unit = {
    println(digestExample())
    println(macExample())
  }
}