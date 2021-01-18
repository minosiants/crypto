package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class PGPEncryptionExample
{

    /**
     * Create an encrypted data blob using an AES-256 session key and the
     * passed in public key.
     *
     * @param encryptionKey the public key to use.
     * @param data the data to be encrypted.
     * @return a PGP binary encoded version of the encrypted data.
     */
    public static byte[] createEncryptedData(
        PGPPublicKey encryptionKey,
        byte[] data)
        throws PGPException, IOException
    {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom()).setProvider("BC"));

        encGen.addMethod(
            new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                .setProvider("BC"));

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        // create an indefinite length encrypted stream
        OutputStream cOut = encGen.open(encOut, new byte[4096]);

        // write out the literal data
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(
            cOut, PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE, data.length, new Date());
        pOut.write(data);
        pOut.close();

        // finish the encryption
        cOut.close();

        return encOut.toByteArray();
    }


    /**
     * Extract the plain text data from the passed in encoding of PGP
     * encrypted data. The routine assumes the passed in private key
     * is the one that matches the first encrypted data object in the
     * encoding.
     *
     * @param privateKey the private key to decrypt the session key with.
     * @param pgpEncryptedData the encoding of the PGP encrypted data.
     * @return a byte array containing the decrypted data.
     */
    public static byte[] extractPlainTextData(
        PGPPrivateKey privateKey,
        byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

        // find the matching public key encrypted data packet.
        PGPPublicKeyEncryptedData encData = null;
        for (PGPEncryptedData pgpEnc: encList)
        {
            PGPPublicKeyEncryptedData pkEnc
                = (PGPPublicKeyEncryptedData)pgpEnc;
            if (pkEnc.getKeyID() == privateKey.getKeyID())
            {
                encData = pkEnc;
                break;
            }
        }

        if (encData == null)
        {
            throw new IllegalStateException("matching encrypted data not found");
        }

        // build decryptor factory
        PublicKeyDataDecryptorFactory dataDecryptorFactory =
            new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC")
                .build(privateKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();

        // check data decrypts okay
        if (encData.verify())
        {
            // parse out literal data
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();
            byte[] data = Streams.readAll(litData.getInputStream());
            return data;
        }
        throw new IllegalStateException("modification check failed");
    }

    private static void elgamalExample()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH", "BC");
        kpGen.initialize(2048);

        KeyPair kp = kpGen.generateKeyPair();

        PGPKeyPair elgKp = new JcaPGPKeyPair(
            PGPPublicKey.ELGAMAL_ENCRYPT, kp, new Date());

        byte[] encData = createEncryptedData(elgKp.getPublicKey(), msg);

        byte[] decData = extractPlainTextData(elgKp.getPrivateKey(), encData);

        System.out.println(Strings.fromByteArray(decData));
    }

    private static void ecExample()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kp = kpGen.generateKeyPair();

        PGPKeyPair ecdhKp = new JcaPGPKeyPair(PGPPublicKey.ECDH, kp, new Date());

        byte[] encData = createEncryptedData(ecdhKp.getPublicKey(), msg);

        byte[] decData = extractPlainTextData(ecdhKp.getPrivateKey(), encData);

        System.out.println(Strings.fromByteArray(decData));
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        elgamalExample();
        ecExample();
    }
}

