package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Pack;

public class XMSSUtils
{
    /**
     * Generate a XMSS key pair with a tree height of 10, based around SHA-512.
     *
     * @return an XMSS KeyPair
     */
    public static KeyPair generateXMSSKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(XMSSParameterSpec.SHA2_10_512);

        return kpg.generateKeyPair();
    }

    /**
     * Return the index used in creating an XMSS signature.
     *
     * @return the index used for the encoded signature.
     */
    public static long getXMSSSignatureIndex(byte[] xmssSig)
    {
        return Pack.bigEndianToInt(xmssSig, 0) & 0xFFFFFFFFL;
    }
}
