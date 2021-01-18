package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import static chapter7.Utils.createTestAESKey;

/**
 * Simple example showing secret key wrapping and unwrapping based on
 * ElGamal OAEP.
 */
public class OAEPExampleWithElGamal
{
    /**
     * Generate a 2048 bit DH key pair using provider based parameters.
     *
     * @return a DH KeyPair
     */
    public static KeyPair generateDHKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BC");

        keyPair.initialize(2048);

        return keyPair.generateKeyPair();
    }

    /**
     * Generate a wrapped key using the OAEP algorithm,
     * returning the resulting encryption.
     *
     * @param dhPublic the public key to base the wrapping on.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(
        PublicKey dhPublic, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
            "ElGamal/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.WRAP_MODE, dhPublic);

        return cipher.wrap(secretKey);
    }

    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param dhPrivate the private key to use for the unwrap.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(
        PrivateKey dhPrivate, byte[] wrappedKey, String keyAlgorithm)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
            "ElGamal/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.UNWRAP_MODE, dhPrivate);

        return (SecretKey)cipher.unwrap(
                              wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        SecretKey aesKey = createTestAESKey();

        KeyPair kp = generateDHKeyPair();

        byte[] wrappedKey = keyWrapOAEP(kp.getPublic(), aesKey);

        SecretKey recoveredKey = keyUnwrapOAEP(
                                    kp.getPrivate(),
                                    wrappedKey, aesKey.getAlgorithm());

        System.out.println(
            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
