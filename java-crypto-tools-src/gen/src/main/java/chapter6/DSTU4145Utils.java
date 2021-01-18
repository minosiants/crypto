package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class DSTU4145Utils
{
    /**
     * Generate a DSTU 4145-2002 key pair for the passed in named parameter set.
     *
     * @param curveNo the curve number to use (range [0-9])
     * @return a EC KeyPair
     */
    public static KeyPair generateDSTU4145KeyPair(int curveNo)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(
                                    "DSTU4145", "BC");

        keyPair.initialize(
            new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + curveNo));

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded DSTU 4145 signature based on the SM3 digest using the
     * passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateDSTU4145Signature(
        PrivateKey ecPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("DSTU4145", "BC");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in DSTU 4145 signature verifies against
     * the passed in EC public key and input.
     *
     * @param ecPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyDSTU4145Signature(
        PublicKey ecPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("DSTU4145", "BC");

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
