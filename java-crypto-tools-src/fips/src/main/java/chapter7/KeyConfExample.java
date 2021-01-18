package chapter7;

import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.crypto.util.ByteMacData;
import org.bouncycastle.jcajce.AgreedKeyWithMacKey;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static chapter7.ECDHUtils.calculateMAC;
import static chapter7.ECDHUtils.generateECKeyPair;
import static chapter7.ECDHUtils.keyConfGenerateAESKey;

/**
 * Key Confirmation example showing use of two key pairs
 * per party in the protocol, with one set being regarded as ephemeral.
 */
public class KeyConfExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Generate the key pairs for party A and party B
        KeyPair aKpS = generateECKeyPair();
        KeyPair aKpE = generateECKeyPair();    // A's ephemeral pair
        KeyPair bKpS = generateECKeyPair();
        KeyPair bKpE = generateECKeyPair();    // B's ephemeral pair

        // key agreement generating an AES key
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        // byte mac data
        ByteMacData byteMacData = new ByteMacData.Builder(
                ByteMacData.Type.BILATERALU,
                Strings.toByteArray("Party A"),    // party A ID
                Strings.toByteArray("Party B"),    // party B ID
                aKpE.getPublic().getEncoded(),        // ephemeral data A
                bKpE.getPublic().getEncoded())        // ephemeral data B
            .withText(Strings.toByteArray("hello, world!")) // optional shared
            .build();

        // A side.
        AgreedKeyWithMacKey aKey = keyConfGenerateAESKey(
            aKpS.getPrivate(),
            aKpE.getPublic(), aKpE.getPrivate(),
            bKpS.getPublic(), bKpE.getPublic(), keyMaterial);

        byte[] aTag = calculateMAC(aKey.getMacKey(), byteMacData.getMacData());

        // B side.
        AgreedKeyWithMacKey bKey = keyConfGenerateAESKey(
            bKpS.getPrivate(),
            bKpE.getPublic(), bKpE.getPrivate(),
            aKpS.getPublic(), aKpE.getPublic(), keyMaterial);

        byte[] bTag = calculateMAC(bKey.getMacKey(), byteMacData.getMacData());

        // compare the two return values.
        System.err.println("keys equal: "
            + Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
        System.err.println("tags equal: "
            + Arrays.areEqual(aTag, bTag));
    }
}
