package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Strings;

import static chapter15.XMSSUtils.generateXMSSKeyPair;

/**
 * Basic example of XMSS with SHA-512 as the tree digest.
 */
public class XMSSExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        byte[] msg = Strings.toByteArray("hello, world!");

        KeyPair kp = generateXMSSKeyPair();

        Signature xmssSig = Signature.getInstance("XMSS", "BCPQC");

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = xmssSig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        System.err.println("XMSS verified: " + xmssSig.verify(s));
    }
}
