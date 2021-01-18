package chapter7;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;

public class RsaKemsUtils
{
    /**
     * Generate a wrapped key using the RSA-KTS-KEM-KWS algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param ktsSpec key transport parameters.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapKEMS(
        PublicKey rsaPublic, KTSParameterSpec ktsSpec, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        cipher.init(Cipher.WRAP_MODE, rsaPublic, ktsSpec);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that is encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param ktsSpec key transport parameters.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapKEMS(
        PrivateKey rsaPrivate, KTSParameterSpec ktsSpec,
        byte[] wrappedKey, String keyAlgorithm)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, ktsSpec);

        return (SecretKey)cipher.unwrap(
                                  wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
}
