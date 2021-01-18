package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class GostR3410_2012Utils
{
    /**
     * Generate a GOST 3410-2012 key pair for the passed in named parameter set.
     *
     * @param paramSetName the name of the parameter set to base the key pair on.
     * @return a EC KeyPair
     */
    public static KeyPair generateGOST3410_2012KeyPair(String paramSetName)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(
                                    "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec(paramSetName));

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded GOST 3410-2012 signature using the passed in
     * GOST 3410-2012 private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @param sigName the name of the signature algorithm to use.
     * @return the encoded signature.
     */
    public static byte[] generateGOST3410_2012Signature(
        PrivateKey ecPrivate, byte[] input, String sigName)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance(sigName, "BC");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in GOST 3410-2012 signature verifies against
     * the passed in GOST 3410-2012 public key and input.
     *
     * @param ecPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param sigName the name of the signature algorithm to use.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyGOST3410_2012Signature(
        PublicKey ecPublic, byte[] input,
        String sigName, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance(sigName, "BC");

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
