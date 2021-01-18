package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;

public class RsaUtils
{
    /**
     * Generate a 2048 bit RSA key pair using user specified parameters.
     *
     * @return a RSA KeyPair
     */
    public static KeyPair generateRSAKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

        keyPair.initialize(
            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generatePKCS1dot5Signature(
        PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyPKCS1dot5Signature(
        PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateRSAPSSSignature(
        PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyRSAPSSSignature(
        PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateRSAPSSSignature(
        PrivateKey rsaPrivate, PSSParameterSpec pssSpec, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSAPSS", "BC");

        signature.setParameter(pssSpec);

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyRSAPSSSignature(
        PublicKey rsaPublic, PSSParameterSpec pssSpec,
        byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSAPSS", "BC");

        signature.setParameter(pssSpec);

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
