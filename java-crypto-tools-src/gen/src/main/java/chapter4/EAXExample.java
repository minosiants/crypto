package chapter4;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;
import static chapter4.AEADUtils.eaxDecrypt;
import static chapter4.AEADUtils.eaxEncrypt;

/**
 * A simple main for using the EAX methods.
 */
public class EAXExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        System.out.println("msg  : " + Hex.toHexString(msg));

        byte[] cText = eaxEncrypt(aesKey, iv, msg);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = eaxDecrypt(aesKey, iv, cText);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
