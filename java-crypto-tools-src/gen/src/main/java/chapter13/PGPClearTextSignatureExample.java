package chapter13;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

import chapter6.DsaUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
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

public class PGPClearTextSignatureExample
{
    // return true if b is a white space character.
    static boolean isWhiteSpace(
        byte b)
    {
        return b == '\r' || b == '\n' || b == '\t' || b == ' ';
    }

    // note: trailing white space needs to be removed from the end of
    // each line for signature calculation RFC 4880 Section 7.1
    static int getLengthWithoutWhiteSpace(
        byte[] line)
    {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end]))
        {
            end--;
        }

        return end + 1;
    }

    // add the leading bytes of line to the signature generator and
    // the full line to the output stream.
    private static void processLine(
        PGPSignatureGenerator sGen, OutputStream aOut, byte[] line)
        throws IOException
    {
        // remove trailing white space.
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0)
        {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);
    }

    // read a line of input, dealing with a variety of line endings.
    private static byte[] readInputLine(
        InputStream fIn)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;

        while ((ch = fIn.read()) >= 0)
        {
            bOut.write(ch);
            if (ch == '\r')
            {
                fIn.mark(1);
                if ((ch = fIn.read()) == '\n')
                {
                    bOut.write(ch);
                }
                else
                {
                    fIn.reset();
                }
                return bOut.toByteArray();
            }
            else if (ch == '\n')
            {
                return bOut.toByteArray();
            }
        }

        return null;
    }

    /**
     * Create a cleartext signed document from the passed in input stream.
     *
     * @param pgpPrivKey the private key to sign with.
     * @param digest the digest algorithm to create the signature with.
     * @param msgIn the input to be included and signed in the message.
     * @param clrOut the output stream to write the cleartext signed document to.
     */
    public static void createCleartextSignature(
        PGPPrivateKey pgpPrivKey, int digest, InputStream msgIn, OutputStream clrOut)
        throws PGPException, IOException
    {
        BufferedInputStream mIn = new BufferedInputStream(msgIn);

        // set up the signature generator.
        int keyAlgorithm = pgpPrivKey.getPublicKeyPacket().getAlgorithm();
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(keyAlgorithm, digest).setProvider("BC"));

        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

        // create the cleartext document.
        ArmoredOutputStream aOut = new ArmoredOutputStream(clrOut);

        aOut.beginClearText(digest);

        //
        // note the last \n/\r/\r\n in the file is ignored
        //
        byte[] line = readInputLine(mIn);

        processLine(sGen, aOut, line);

        while ((line = readInputLine(mIn)) != null)
        {
            sGen.update((byte)'\r');
            sGen.update((byte)'\n');

            processLine(sGen, aOut, line);
        }

        // end the cleartext data
        aOut.endClearText();

        // output the signature block
        sGen.generate().encode(aOut);

        aOut.close();
    }

    // process a line, ignoring trailing white space.
    private static void processLine(PGPSignature sig, byte[] line)
    {
        // remove trailing white space.
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0)
        {
            sig.update(line, 0, length);
        }
    }

    // process the input data for signature verification.
    static void processInput(PGPSignature sig, InputStream sigIn)
        throws IOException
    {
        byte[] lookAhead = readInputLine(sigIn);

        processLine(sig, lookAhead);

        if (lookAhead != null)
        {
            while ((lookAhead = readInputLine(sigIn)) != null)
            {
                sig.update((byte)'\r');
                sig.update((byte)'\n');

                processLine(sig, lookAhead);
            }
        }

        sigIn.close();
    }

    /**
     * Verify the passed in cleartext signed document, returning true and a copy
     * of the data if successful, false otherwise.
     *
     * @param publicKey the public key to verify the signature with.
     * @param in the input containing the cleartext signed document.
     * @param msgOut the output stream to save the signed data in.
     * @return true if the document verifies, false otherwise.
     */
    public static boolean verifyCleartextSignature(
        PGPPublicKey publicKey, InputStream in, OutputStream msgOut)
        throws IOException, PGPException
    {
        ArmoredInputStream aIn = new ArmoredInputStream(in);

        // save a copy of the text for verification
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = aIn.read()) > 0 && aIn.isClearText())
        {
            bOut.write(ch);
        }

        //
        // load the signature record in the "PGP SIGNATURE" block.
        //
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        if (publicKey.getKeyID() != sig.getKeyID())
        {
            throw new PGPException("public key not for signature in document");
        }

        sig.init(
           new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

        //
        // read the input, making sure we ignore the last newline.
        //
        InputStream sigIn = new ByteArrayInputStream(bOut.toByteArray());

        processInput(sig, sigIn);

        if (sig.verify())
        {
            msgOut.write(bOut.toByteArray());
            msgOut.flush();

            return true;
        }

        return false;
    }
    
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] message = Strings.toByteArray("Hello, world!\r\n");
        KeyPair dsaKp = DsaUtils.generateDSAKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());

        ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
        createCleartextSignature(
            dsaKeyPair.getPrivateKey(), PGPUtil.SHA256,
            new ByteArrayInputStream(message), sigOut);

        System.out.println(Strings.fromByteArray(sigOut.toByteArray()));

        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();

        if (verifyCleartextSignature(
                dsaKeyPair.getPublicKey(),
                new ByteArrayInputStream(sigOut.toByteArray()),
                msgOut))
        {
            System.out.println(Strings.fromByteArray(msgOut.toByteArray()));
        }
        else
        {
            System.out.println("message failed to verify");
        }
    }
}
