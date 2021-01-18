package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter7.RsaUtils.keyUnwrapOAEP;
import static chapter7.RsaUtils.keyWrapOAEP;
import static chapter7.Utils.createTestAESKey;

/**
 * Simple example showing secret key wrapping and unwrapping based on OAEP
 * and using the OAEPParameterSpec class to configure the encryption.
 */
public class OAEPParamsExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        SecretKey aesKey = createTestAESKey();

        KeyPair kp = generateRSAKeyPair();
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                                        "SHA-256",
                                        "MGF1", MGF1ParameterSpec.SHA256,
                                            new PSource.PSpecified(
                                              Strings.toByteArray("My Label")));

        byte[] wrappedKey = keyWrapOAEP(kp.getPublic(), aesKey);

        SecretKey recoveredKey = keyUnwrapOAEP(
                                    kp.getPrivate(), oaepSpec,
                                    wrappedKey, aesKey.getAlgorithm());

        System.out.println(
            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
