package chapter3;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter3.JcaUtils.computeDigest;

/**
 * A simple example of using a MessageDigest.
 */
public class DigestExample
{
    public static void main(String[] args)
        throws Exception
    {
        System.out.println(
            Hex.toHexString(
                computeDigest("SHA-256", Strings.toByteArray("Hello World!"))));
    }
}
