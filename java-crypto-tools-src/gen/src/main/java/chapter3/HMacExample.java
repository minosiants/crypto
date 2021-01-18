package chapter3;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter3.JcaUtils.computeDigest;
import static chapter3.JceUtils.computeMac;

/**
 * A simple example of using a HMAC SHA-256.
 */
public class HMacExample
{
    public static void main(String[] args)
        throws Exception
    {     Security.addProvider(new BouncyCastleProvider());
        SecretKey macKey = new SecretKeySpec(
                Hex.decode(
                    "2ccd85dfc8d18cb5d84fef4b19855469" +
                    "9fece6e8692c9147b0da983f5b7bd413"), "HmacSHA256");

        System.out.println(
            Hex.toHexString(
                computeMac("HmacSHA256", macKey,
                                 Strings.toByteArray("Hello World!"))));
    }
}
