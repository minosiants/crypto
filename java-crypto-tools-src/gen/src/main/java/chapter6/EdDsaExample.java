package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static chapter6.EdDsaUtils.generateEdDSASignature;
import static chapter6.EdDsaUtils.generateEd448KeyPair;
import static chapter6.EdDsaUtils.verifyEdDSASignature;

/**
 * Simple example of the use of the EdDSA methods for Ed448.
 */
public class EdDsaExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateEd448KeyPair();

        byte[] ecdsaSignature = generateEdDSASignature(ecKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("EdDSA verified: " + verifyEdDSASignature(
            ecKp.getPublic(), Strings.toByteArray("hello, world!"), ecdsaSignature));
    }
}
