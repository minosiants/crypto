package chapter4;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import static chapter4.AEADUtils.createConstantKey;

/**
 * An example of use of a SealedObject to protect a serializable object. In this
 * case we use a private key, but any serializable will do.
 */
public class SealedObjectExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        // create our interesting serializable
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048);

        KeyPair kp = kpGen.generateKeyPair();

        // initialize the "sealing cipher"
        Cipher wrapCipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");

        wrapCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        // create the sealed object from the serializable
        SealedObject sealed = new SealedObject(kp.getPrivate(), wrapCipher);

        // simulate a "wire transfer" of the sealed object.
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream    oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(sealed);

        oOut.close();

        SealedObject transmitted = (SealedObject)new ObjectInputStream(
            new ByteArrayInputStream(bOut.toByteArray())).readObject();

        // unseal transmitted, extracting the private key
        PrivateKey unwrappedKey =
                       (PrivateKey)transmitted.getObject(aesKey, "BC");

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
                kp.getPrivate().getEncoded(), unwrappedKey.getEncoded()));
    }
}
