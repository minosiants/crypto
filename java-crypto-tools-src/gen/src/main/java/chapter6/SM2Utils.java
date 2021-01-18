package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;

public class SM2Utils
{
    /**
     * Generate an encoded SM2 signature based on the SM3 digest using the
     * passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateSM2Signature(
        PrivateKey ecPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in SM3withSM2 signature verifies against
     * the passed in EC public key and input.
     *
     * @param ecPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifySM2Signature(
        PublicKey ecPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded SM2 signature based on the SM3 digest using the
     * passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param sm2Spec the SM2 specification carrying the ID of the signer.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateSM2Signature(
        PrivateKey ecPrivate, SM2ParameterSpec sm2Spec, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.setParameter(sm2Spec);

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in SM3withSM2 signature verifies against
     * the passed in EC public key and input.
     *
     * @param ecPublic the public key of the signature creator.
     * @param sm2Spec the SM2 specification carrying the expected ID of the signer.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifySM2Signature(
        PublicKey ecPublic, SM2ParameterSpec sm2Spec,
        byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.setParameter(sm2Spec);

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
