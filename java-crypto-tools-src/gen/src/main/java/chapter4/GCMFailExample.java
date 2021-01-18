package chapter4;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;
import static chapter4.AEADUtils.gcmDecrypt;
import static chapter4.AEADUtils.gcmEncrypt;

/**
 * A simple GCM example that shows data corruption.
 */
public class GCMFailExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        byte[] cText = gcmEncrypt(aesKey, iv, 128, msg);

        // tamper with the cipher text
        cText[0] = (byte)~cText[0];

        byte[] pText = gcmDecrypt(aesKey, iv, 128, cText);
    }
}
