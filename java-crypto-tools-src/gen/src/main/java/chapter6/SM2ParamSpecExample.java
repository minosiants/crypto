package chapter6;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.util.Strings;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter6.SM2Utils.generateSM2Signature;
import static chapter6.SM2Utils.verifySM2Signature;

/**
 * An example of using SM2 with an SM2ParameterSpec to specify the ID string
 * for the signature.
 */
public class SM2ParamSpecExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateECKeyPair("sm2p256v1");

        SM2ParameterSpec sm2Spec = new SM2ParameterSpec(
                             Strings.toByteArray("Signer@Octets.ID"));

        byte[] sm2Signature = generateSM2Signature(
                                    ecKp.getPrivate(), sm2Spec,
                                    Strings.toByteArray("hello, world!"));

        System.out.println("SM2 verified: "
               + verifySM2Signature(
                    ecKp.getPublic(), sm2Spec,
                    Strings.toByteArray("hello, world!"), sm2Signature));
    }
}
