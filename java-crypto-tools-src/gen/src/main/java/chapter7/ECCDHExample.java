package chapter7;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter7.ECDHUtils.ecGenerateAESKey;

public class ECCDHExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Generate the key pairs for party A and party B
        KeyPair aKp = generateECKeyPair();
        KeyPair bKp = generateECKeyPair();

        // key agreement generating a shared secret
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        SecretKey aKey = ecGenerateAESKey(
            aKp.getPrivate(), bKp.getPublic(), keyMaterial);
        SecretKey bKey = ecGenerateAESKey(
            bKp.getPrivate(), aKp.getPublic(), keyMaterial);

        // compare the two return values.
        System.out.println(
            Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
    }
}
