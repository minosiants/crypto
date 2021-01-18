package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter7.RsaUtils.keyUnwrapOAEP;
import static chapter7.RsaUtils.keyWrapOAEP;
import static chapter7.Utils.createTestAESKey;

/**
 * Simple example showing secret key wrapping and unwrapping based on OAEP.
 */
public class OAEPExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        SecretKey aesKey = createTestAESKey();

        KeyPair kp = generateRSAKeyPair();

        byte[] wrappedKey = keyWrapOAEP(kp.getPublic(), aesKey);
        
        SecretKey recoveredKey = keyUnwrapOAEP(
                                    kp.getPrivate(),
                                    wrappedKey, aesKey.getAlgorithm());

        System.out.println(
            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
