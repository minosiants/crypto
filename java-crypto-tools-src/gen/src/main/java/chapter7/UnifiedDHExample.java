package chapter7;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static chapter7.DHUtils.dhuGenerateAESKey;
import static chapter7.DHUtils.generateDHKeyPair;

/**
 * Basic Unified Diffie-Hellman example showing use of two key pairs
 * per party in the protocol, with one set being regarded as ephemeral.
 */
public class UnifiedDHExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Generate the key pairs for party A and party B
        KeyPair aKpS = generateDHKeyPair();
        KeyPair aKpE = generateDHKeyPair();    // A's ephemeral pair
        KeyPair bKpS = generateDHKeyPair();
        KeyPair bKpE = generateDHKeyPair();    // B's ephemeral pair

        // key agreement generating an AES key
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        SecretKey aKey = dhuGenerateAESKey(
            aKpS.getPrivate(),
            aKpE.getPublic(), aKpE.getPrivate(),
            bKpS.getPublic(), bKpE.getPublic(), keyMaterial);
        SecretKey bKey = dhuGenerateAESKey(
            bKpS.getPrivate(),
            bKpE.getPublic(), bKpE.getPrivate(),
            aKpS.getPublic(), aKpE.getPublic(), keyMaterial);

        // compare the two return values.
        System.out.println(
            Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
    }
}
