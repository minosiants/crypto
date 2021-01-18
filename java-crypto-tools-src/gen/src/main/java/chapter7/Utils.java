package chapter7;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.util.encoders.Hex;

public class Utils
{
    /**
     * Create a test AES key.
     *
     * @return a constant AES key.
     */
    static SecretKey createTestAESKey()
    {

        return new SecretKeySpec(
                       Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
    }
}
