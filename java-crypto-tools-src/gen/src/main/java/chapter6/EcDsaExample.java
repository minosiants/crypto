package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.bouncycastle.util.Strings;

import static chapter6.EcDsaUtils.generateECDSASignature;
import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter6.EcDsaUtils.verifyECDSASignature;

/**
 * Simple example of the use of the ECDSA methods for signature generation.
 */
public class EcDsaExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateECKeyPair();

        byte[] ecdsaSignature = generateECDSASignature(ecKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("DSA verified: " + verifyECDSASignature(
            ecKp.getPublic(), Strings.toByteArray("hello, world!"), ecdsaSignature));
    }
}
