package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.bouncycastle.util.Strings;

import static chapter6.DSTU4145Utils.generateDSTU4145KeyPair;
import static chapter6.DSTU4145Utils.generateDSTU4145Signature;
import static chapter6.DSTU4145Utils.verifyDSTU4145Signature;

/**
 * An example of using DSTU 4145-2002 to sign data and then
 * verifying the resulting signature.
 */
public class DSTU4145Example
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateDSTU4145KeyPair(0);

        byte[] dstuSig = generateDSTU4145Signature(
            ecKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("DSTU 4145-2002 verified: " +
                    verifyDSTU4145Signature(
                        ecKp.getPublic(), Strings.toByteArray("hello, world!"),
                         dstuSig));
    }
}
