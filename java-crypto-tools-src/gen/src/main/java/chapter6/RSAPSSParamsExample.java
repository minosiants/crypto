package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.util.Strings;

import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter6.RsaUtils.generateRSAPSSSignature;
import static chapter6.RsaUtils.verifyRSAPSSSignature;

/**
 * An example of using RSA PSS with a PSSParameterSpec based on SHA-256.
 */
public class RSAPSSParamsExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair rsaKp = generateRSAKeyPair();
        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256",
            "MGF1", new MGF1ParameterSpec("SHA-256"), 32,
            1);

        byte[] pssSignature = generateRSAPSSSignature(
            rsaKp.getPrivate(), pssSpec, Strings.toByteArray("hello, world!"));

        System.out.println("RSA PSS verified: "
                                + verifyRSAPSSSignature(
                                        rsaKp.getPublic(), pssSpec,
                                        Strings.toByteArray("hello, world!"),
                                        pssSignature));
    }
}
