package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

public class JcaUtils
{
    public static KeyPair generateKeyPairUsingSize(
        String algorithm, int size)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(size);

        return kpGen.generateKeyPair();
    }

    public static KeyPair generateKeyPairUsingParameters(
        String algorithm, AlgorithmParameterSpec keyGenSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(keyGenSpec);

        return kpGen.generateKeyPair();
    }

    /**
     * Return a public key for algorithm built from the details in keySpec.
     *
     * @param algorithm the algorithm the key specification is for.
     * @param keySpec a key specification holding details of the public key.
     * @return a PublicKey for algorithm
     */
    public static PublicKey createPublicKey(String algorithm, KeySpec keySpec)
        throws GeneralSecurityException
    {
        KeyFactory keyFact = KeyFactory.getInstance(algorithm, "BC");

        return keyFact.generatePublic(keySpec);
    }

    /**
     * Return a private key for algorithm built from the details in keySpec.
     *
     * @param algorithm the algorithm the key specification is for.
     * @param keySpec a key specification holding details of the private key.
     * @return a PrivateKey for algorithm
     */
    public static PrivateKey createPrivateKey(String algorithm, KeySpec keySpec)
        throws GeneralSecurityException
    {
        KeyFactory keyFact = KeyFactory.getInstance(algorithm, "BC");

        return keyFact.generatePrivate(keySpec);
    }
}
