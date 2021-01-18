package chapter4;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.ccmDecryptWithAAD;
import static chapter4.AEADUtils.ccmEncryptWithAAD;
import static chapter4.AEADUtils.createConstantKey;

/**
 * A simple CCM Example with Additional Associated Data (AAD)
 */
public class CCMWithAADExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");

        System.out.println("msg  : " + Hex.toHexString(msg));
        
        byte[] cText = ccmEncryptWithAAD(aesKey, iv, msg, aad);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = ccmDecryptWithAAD(aesKey, iv, cText, aad);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
