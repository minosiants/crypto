package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class EcDsaUtils
{
    /**
     * Generate a EC key pair on the passed in named curve.
     *
     * @param curveName the name of the curve to generate the key pair on.
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair(String curveName)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BC");

        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }
    /**
     * Generate a EC key pair on the P-256 curve.
     *
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair()
        throws GeneralSecurityException
    {
        return generateECKeyPair("P-256");
    }
    /**
     * Generate an encoded ECDSA signature using the passed in EC private key
     * and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateECDSASignature(
        PrivateKey ecPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in ECDSA signature verifies against
     * the passed in EC public key and input.
     *
     * @param ecPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyECDSASignature(
        PublicKey ecPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded Deterministic ECDSA (ECDDSA) signature using the
     * passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateECDDSASignature(
        PrivateKey ecPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withECDDSA", "BC");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
}
