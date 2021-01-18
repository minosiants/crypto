package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Pack;

public class LMSUtils
{
    /**
     * Generate a LMS key pair with a tree height of 5, based around SHA-256.
     *
     * @return an LMS KeyPair
     */
    public static KeyPair generateLMSKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        kpg.initialize(new LMSKeyGenParameterSpec(
                                LMSigParameters.lms_sha256_n32_h5,
                                LMOtsParameters.sha256_n32_w1));

        return kpg.generateKeyPair();
    }

    /**
     * Generate a HSS key pair with a tree height of 10, based around SHA-256.
     *
     * @return an HSS KeyPair
     */
    public static KeyPair generateHSSKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        kpg.initialize(new LMSHSSKeyGenParameterSpec(
            new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5,
                                            LMOtsParameters.sha256_n32_w1),
            new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5,
                                            LMOtsParameters.sha256_n32_w1)));

        return kpg.generateKeyPair();
    }

    /**
     * Return the index used in creating an LMS signature.
     *
     * @return the index used for the encoded signature.
     */
    public static long getLMSSignatureIndex(byte[] lmsSig)
    {
        return Pack.bigEndianToInt(lmsSig, 0) & 0xFFFFFFFFL;
    }
}
