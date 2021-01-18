package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.bouncycastle.util.Strings;

import static chapter6.GostR3410_2012Utils.generateGOST3410_2012KeyPair;
import static chapter6.GostR3410_2012Utils.generateGOST3410_2012Signature;
import static chapter6.GostR3410_2012Utils.verifyGOST3410_2012Signature;

/**
 * An example of using GOST R 34.10-2012 to sign data and then
 * verifying the resulting signature.
 */
public class GostR3410_2012Example
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateGOST3410_2012KeyPair(
                            "Tc26-Gost-3410-12-512-paramSetA");

        byte[] ecGostSig = generateGOST3410_2012Signature(
            ecKp.getPrivate(), Strings.toByteArray("hello, world!"),
            "ECGOST3410-2012-512");

        System.err.println("ECGOST3410-2012-512 verified: " +
                    verifyGOST3410_2012Signature(
                        ecKp.getPublic(), Strings.toByteArray("hello, world!"),
                        "ECGOST3410-2012-512", ecGostSig));
    }
}
