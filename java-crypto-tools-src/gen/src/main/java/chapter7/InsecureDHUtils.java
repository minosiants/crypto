package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

import static chapter7.DHUtils.generateDHKeyPair;

public class InsecureDHUtils
{
    // Set up constant secure random to produce constant private keys with
    private static SecureRandom insecureRandom = new FixedSecureRandom(
        new FixedSecureRandom.Source[] {
        new FixedSecureRandom.BigInteger(256,
            Hex.decode(
                "914bb9b3d677c4ce87e5f671a88c85c0" +
                    "615228c6f7d6fbfdee89092f69609128")),
        new FixedSecureRandom.BigInteger(256,
            Hex.decode(
                "837028bb0ccdaf1cf9a390b1f84bf916" +
                    "999ba4760d4297124ca991a1e616b676")) });


    private static DHParameterSpec dhSpec;

    /**
     * Initialize our Diffie-Hellman parameters for key pair generation
     */
    static void insecureUtilsInit()
        throws GeneralSecurityException
    {
        // Grab a regular parameter set and tailor it for keys with a 256 bit
        // private value.
        KeyPair kp = generateDHKeyPair();
        dhSpec = ((DHPublicKey)kp.getPublic()).getParams();
        dhSpec = new DHParameterSpec(dhSpec.getP(), dhSpec.getG(), 256);
    }

    /**
     * Generate a key pair using our constant random source.
     * @return a Diffie-Hellman key pair.
     */
    static KeyPair insecureGenerateDHKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH", "BC");

        keyPairGen.initialize(dhSpec, insecureRandom);

        return keyPairGen.generateKeyPair();
    }
}
