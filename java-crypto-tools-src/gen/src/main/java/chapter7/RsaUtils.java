package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;

public class RsaUtils
{
    /**
     * Generate a wrapped key using the RSA OAEP algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(
        PublicKey rsaPublic, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
            "RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.WRAP_MODE, rsaPublic);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(
        PrivateKey rsaPrivate, byte[] wrappedKey, String keyAlgorithm)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
            "RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate);

        return (SecretKey)cipher.unwrap(
                              wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
    /**
     * Generate a wrapped key using the RSA OAEP algorithm according
     * to the passed in OAEPParameterSpec and return the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param oaepSpec the parameter specification for the OAEP operation.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(
        PublicKey rsaPublic, OAEPParameterSpec oaepSpec, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");

        cipher.init(Cipher.WRAP_MODE, rsaPublic, oaepSpec);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param oaepSpec the parameter specification for the OAEP operation.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(
        PrivateKey rsaPrivate, OAEPParameterSpec oaepSpec,
        byte[] wrappedKey, String keyAlgorithm)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, oaepSpec);

        return (SecretKey)cipher.unwrap(
                             wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
}
