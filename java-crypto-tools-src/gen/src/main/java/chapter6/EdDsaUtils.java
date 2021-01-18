package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class EdDsaUtils
{
    /**
     * Generate a EdDSA key pair for Ed448.
     *
     * @return a EdDSA KeyPair
     */
    public static KeyPair generateEd448KeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("Ed448", "BC");

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded EdDSA signature using the passed in EdDSA private key
     * and input data.
     *
     * @param edPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateEdDSASignature(
        PrivateKey edPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("EdDSA", "BC");

        signature.initSign(edPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in EdDSA signature verifies against
     * the passed in EdDSA public key and input.
     *
     * @param edPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyEdDSASignature(
        PublicKey edPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("EdDSA", "BC");

        signature.initVerify(edPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
