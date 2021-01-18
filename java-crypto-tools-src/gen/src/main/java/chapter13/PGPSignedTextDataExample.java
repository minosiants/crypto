package chapter13;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.Strings;

import static chapter13.PGPSignedDataExample.verifySignedMessage;

public class PGPSignedTextDataExample
{
    /**
     * Create a PGP signed text message based on the passed in signing key
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

        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, signingKey);

        // Output the signature header
        // the false means we are not generating a nested signature.
        sGen.generateOnePassVersion(false).encode(bcOut);

        // Create the Literal Data record
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        OutputStream lOut = lGen.open(bcOut,
            PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, data.length, new Date());

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

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        // platform independent text message generator
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BufferedWriter bWrt = new BufferedWriter(new OutputStreamWriter(bOut));
        bWrt.write("Hello, world!");
        bWrt.newLine();
        bWrt.close();

        byte[] message = bOut.toByteArray();

        KeyPair dsaKp = DsaUtils.generateDSAKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());

        byte[] signedMessage = createSignedMessage(
            PublicKeyAlgorithmTags.DSA, dsaKeyPair.getPrivateKey(), message);

        ByteArrayOutputStream recStream = new ByteArrayOutputStream();
        
        if (verifySignedMessage(dsaKeyPair.getPublicKey(), signedMessage, recStream))
        {
            System.out.print(Strings.fromByteArray(recStream.toByteArray()));
        }
    }
}
