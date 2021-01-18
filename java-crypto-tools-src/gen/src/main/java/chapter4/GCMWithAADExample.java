package chapter4;

import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;
import static chapter4.AEADUtils.gcmDecryptWithAAD;
import static chapter4.AEADUtils.gcmEncryptWithAAD;

/**
 * A simple GCM example with Additional Associated Data (AAD)
 */
public class GCMWithAADExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");

        System.out.println("msg  : " + Hex.toHexString(msg));
        
        byte[] cText = gcmEncryptWithAAD(aesKey, iv, msg, aad);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = gcmDecryptWithAAD(aesKey, iv, cText, aad);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
