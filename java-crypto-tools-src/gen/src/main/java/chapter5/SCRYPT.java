package chapter5;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

import javax.crypto.SecretKeyFactory;
import java.security.GeneralSecurityException;

public class SCRYPT
{
    /**
     * Calculate a derived key using SCRYPT using the BC low-level API.
     *
     * @param password the password input.
     * @param salt the salt parameter.
     * @param costParameter the cost parameter.
     * @param blocksize the blocksize parameter.
     * @param parallelizationParam the parallelization parameter.
     * @return the derived key.
     */
    public static byte[] bcSCRYPT(char[] password, byte[] salt,
                                  int costParameter, int blocksize,
                                  int parallelizationParam)
    {
        return SCrypt.generate(
                PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password),
                salt, costParameter, blocksize, parallelizationParam,
                256 / 8);
    }
    /**
     * Calculate a derived key using SCRYPT using the BC JCE provider.
     *
     * @param password the password input.
     * @param salt the salt parameter.
     * @param costParameter the cost parameter.
     * @param blocksize the blocksize parameter.
     * @param parallelizationParam the parallelization parameter.
     * @return the derived key.
     */
    public static byte[] jceSCRYPT(char[] password, byte[] salt,
                                   int costParameter, int blocksize,
                                   int parallelizationParam)
            throws GeneralSecurityException
    {
        SecretKeyFactory fact = SecretKeyFactory.getInstance(
                                "SCRYPT","BC");

        return fact.generateSecret(
                new ScryptKeySpec(password, salt,
                        costParameter, blocksize, parallelizationParam,
                        256)).getEncoded();
    }
}
