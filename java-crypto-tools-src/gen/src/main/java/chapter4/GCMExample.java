package chapter4;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;
import static chapter4.AEADUtils.gcmDecrypt;
import static chapter4.AEADUtils.gcmEncrypt;

/**
 * A simple GCM example without Additional Associated Data (AAD)
 */
public class GCMExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        System.out.println("msg  : " + Hex.toHexString(msg));

        byte[] cText = gcmEncrypt(aesKey, iv, 128, msg);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = gcmDecrypt(aesKey, iv, 128, cText);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
