package chapter4;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;

/**
 * An example of KW style key wrapping - note in this case the input must be
 * aligned on an 8 byte boundary (for AES).
 */
public class KWExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        SecretKeySpec keyToWrap = new SecretKeySpec(
            Hex.decode("00010203040506070706050403020100"), "Blowfish");

        // wrap the key
        Cipher wrapCipher = Cipher.getInstance("AESKW", "BC");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        byte[] cText = wrapCipher.wrap(keyToWrap);

        // unwrap the key
        Cipher unwrapCipher = Cipher.getInstance("AESKW", "BC");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);

        SecretKey unwrappedKey =
            (SecretKey)unwrapCipher.unwrap(cText, "Blowfish", Cipher.SECRET_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
                                         keyToWrap.getEncoded(),
                                         unwrappedKey.getEncoded()));
    }
}
