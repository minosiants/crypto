package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import chapter6.DsaUtils;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
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

public class PGPDetachedSignedDataExample
{
    /**
     * Generate a detached signature for binary data.
     *
     * @param signingAlg signing algorithm to use.
     * @param signingKey signing key to use.
     * @param data the data to be signed.
     * @return an encoded PGP detached signature.
     */
    public static byte[] createDetachedSignature(
        int signingAlg, PGPPrivateKey signingKey, byte[] data)
        throws PGPException, IOException
    {
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA384)
                                                    .setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        sGen.update(data);

        PGPSignature pgpSig = sGen.generate();

        return pgpSig.getEncoded();
    }

    /**
     * Verify a detached signature for binary data.
     *
     * @param verifyingKey the public key to verify the signature with.
     * @param pgpSignature the signature generated for the data.
     * @param data the data that was signed.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyDetachedSignature(
        PGPPublicKey verifyingKey, byte[] pgpSignature, byte[] data)
        throws PGPException, IOException
    {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignature);

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();

        PGPSignature sig = null;
        for (PGPSignature s: sigList)
        {
            if (s.getKeyID() == verifyingKey.getKeyID())
            {
                sig = s;
                break;
            }
        }

        if (sig == null)
        {
            throw new IllegalStateException("signature for key not found");
        }

        sig.init(
            new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
            verifyingKey);

        sig.update(data);

        return sig.verify();
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] message = Strings.toByteArray("Hello, world!");
        KeyPair dsaKp = DsaUtils.generateDSAKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());

        byte[] signature = createDetachedSignature(
            PublicKeyAlgorithmTags.DSA, dsaKeyPair.getPrivateKey(), message);

        if (verifyDetachedSignature(dsaKeyPair.getPublicKey(), signature, message))
        {
            System.out.println("signature verified");
        }
        else
        {
            System.out.println("signature failed");
        }
    }
}
