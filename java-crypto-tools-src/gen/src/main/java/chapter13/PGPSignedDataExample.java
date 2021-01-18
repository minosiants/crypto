package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

import chapter6.DsaUtils;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.Strings;

public class PGPSignedDataExample
{
    /**
     * Create a PGP signed message based on the passed in signing key
     * and data.
     *
     * @param signingAlg the signature algorithm to use.
     * @param signingKey the PGP private key to sign with.
     * @param data the message data to be signed.
     * @return an encoding of the signed message
     */
    public static byte[] createSignedMessage(
        int signingAlg, PGPPrivateKey signingKey, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        // Create a stream for writing a signature to.
        BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

        // set up the signature generator
        PGPSignatureGenerator sGen =
            new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA384)
                    .setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        // Output the signature header
        // the false means we are not generating a nested signature.
        sGen.generateOnePassVersion(false).encode(bcOut);

        // Create the Literal Data record
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        OutputStream lOut = lGen.open(bcOut,
            PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        for (int i = 0; i != data.length; i++)
        {
            lOut.write(data[i]);
            sGen.update(data[i]);
        }

        // Finish Literal Data construction
        lOut.close();

        // Output the actual signature
        sGen.generate().encode(bcOut);

        // close off the stream.
        bcOut.close();

        return bOut.toByteArray();
    }

    /**
     * Recover the original message in bOut, returning true if the signature verifies.
     * 
     * @param verifyingKey the PGP public key to verify the message with.
     * @param pgpSignedData the PGP signed message data.
     * @param msgStream a stream to write the recovered message to.
     * @return true if the signed message verifies, false otherwise.
     */
    public static boolean verifySignedMessage(
        PGPPublicKey verifyingKey, byte[] pgpSignedData, OutputStream msgStream)
        throws PGPException, IOException
    {
        // Create a parser for the PGP protocol stream
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);

        // Read the signature header and set up the verification
        PGPOnePassSignatureList onePassList
                                    = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = onePassList.get(0);

        ops.init(
            new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
            verifyingKey);

        // Open up the Literal Data record containing the message
        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
        InputStream dIn = literalData.getInputStream();

        // Read the message data
        int ch;
        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
            msgStream.write(ch);
        }

        dIn.close();

        // Read and verify the signature
        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] message = Strings.toByteArray("Hello, world!");
        KeyPair dsaKp = DsaUtils.generateDSAKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());

        byte[] signedMessage = createSignedMessage(
            PublicKeyAlgorithmTags.DSA, dsaKeyPair.getPrivateKey(), message);

        ByteArrayOutputStream recStream = new ByteArrayOutputStream();
        
        if (verifySignedMessage(dsaKeyPair.getPublicKey(), signedMessage, recStream))
        {
            System.out.println(Strings.fromByteArray(recStream.toByteArray()));
        }
    }
}
