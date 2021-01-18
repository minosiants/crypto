package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class PGPPBEEncryptionExample
{
    /**
     * Create an encrypted data blob using an AES-256 key wrapped using
     * a PBE based key.
     *
     * @param passwd the password to apply to generate the PBE based key.
     * @param data the data to be encrypted.
     * @return a PGP binary encoded version of the encrypted data.
     */
    public static byte[] createPBEEncryptedData(
        char[] passwd,
        byte[] data)
        throws PGPException, IOException
    {
        // create the packet containing the plaintext.
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(
            bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
            data.length, new Date());
        pOut.write(data);
        pOut.close();

        byte[] plainText = bOut.toByteArray();

        // set up the generator
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BC"));
        encGen.addMethod(
            new JcePBEKeyEncryptionMethodGenerator(passwd).setProvider("BC"));

        // encryption step.
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream cOut = encGen.open(encOut, plainText.length);
        cOut.write(plainText);
        cOut.close();

        return encOut.toByteArray();
    }

    /**
     * Extract the plain text data from the passed in encoding of PGP
     * encrypted data. The routine assumes the password is matched
     * with the first encrypted data object in the encoding.
     *
     * @param passwd the password to apply to generate the PBE based key.
     * @param pgpEncryptedData the encoding of the PGP encrypted data.
     * @return a byte array containing the decrypted data.
     */
    public static byte[] extractPlainTextPBEData(
        char[] passwd,
        byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPEncryptedDataList encList = new PGPEncryptedDataList(pgpEncryptedData);

        // assume the PBE encrypted data is first.
        PGPPBEEncryptedData encData = (PGPPBEEncryptedData)encList.get(0);
        PBEDataDecryptorFactory dataDecryptorFactory =
            new JcePBEDataDecryptorFactoryBuilder()
                .setProvider("BC")
                .build(passwd);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();

        // check data decrypts okay
        if (encData.verify())
        {
            PGPLiteralData litData = new PGPLiteralData(literalData);
            return Streams.readAll(litData.getInputStream());
        }

        throw new IllegalStateException("modification check failed");
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        
        byte[] msg = Strings.toByteArray("Hello, PBE world!");
        char[] password = "secret".toCharArray();

        byte[] encData = createPBEEncryptedData(password, msg);

        byte[] decData = extractPlainTextPBEData(password, encData);

        System.out.println(Strings.fromByteArray(decData));
    }

}
