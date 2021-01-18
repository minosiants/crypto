package chapter6;

import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static chapter6.DsaUtils.generateDSAKeyPair;
import static chapter6.DsaUtils.generateDSASignature;
import static chapter6.DsaUtils.verifyDSASignature;

public class DsaExample
{
    public static void main(String[] args)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("hello, world!");

        Security.addProvider(new BouncyCastleProvider());
        KeyPair dsaKp = generateDSAKeyPair();

        byte[] dsaSignature = generateDSASignature(dsaKp.getPrivate(), msg);

        System.out.println("DSA verified: " + verifyDSASignature(dsaKp.getPublic(), msg, dsaSignature));
    }
}
