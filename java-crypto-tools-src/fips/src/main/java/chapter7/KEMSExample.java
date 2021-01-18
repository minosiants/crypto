package chapter7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter7.RsaKemsUtils.keyUnwrapKEMS;
import static chapter7.RsaKemsUtils.keyWrapKEMS;

/**
 * Simple example showing secret key wrapping and unwrapping based on RSA-KEMS.
 */
public class KEMSExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        SecretKey aesKey = new SecretKeySpec(
                                Hex.decode("000102030405060708090a0b0c0d0e0f"),
                                "AES");

        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");

        keyPair.initialize(2048);

        KeyPair kp = keyPair.generateKeyPair();

        KTSParameterSpec ktsSpec =
                            new KTSParameterSpec.Builder(
                                "AESKWP", 256,
                                Strings.toByteArray("OtherInfo Data")).build();

        byte[] wrappedKey = keyWrapKEMS(kp.getPublic(), ktsSpec, aesKey);

        SecretKey recoveredKey = keyUnwrapKEMS(
                                    kp.getPrivate(), ktsSpec,
                                    wrappedKey, aesKey.getAlgorithm());

        System.out.println(
            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
