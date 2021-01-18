package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Strings;

import static chapter15.LMSUtils.generateLMSKeyPair;


/**
 * Basic example of LMS with SHA-512 as the tree digest.
 */
public class LMSExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());
        
        byte[] msg = Strings.toByteArray("hello, world!");

        KeyPair kp = generateLMSKeyPair();

        Signature lmsSig = Signature.getInstance("LMS", "BCPQC");

        lmsSig.initSign(kp.getPrivate());

        lmsSig.update(msg, 0, msg.length);

        byte[] s = lmsSig.sign();

        lmsSig.initVerify(kp.getPublic());

        lmsSig.update(msg, 0, msg.length);

        System.err.println("LMS verified: " + lmsSig.verify(s));
    }
}
