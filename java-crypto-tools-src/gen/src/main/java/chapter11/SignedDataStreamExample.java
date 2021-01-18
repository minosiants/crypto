package chapter11;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class SignedDataStreamExample
{
    /**
     * Create a SignedData structure using the streaming API.
     *
     * @param signingKey the key to generate the signature with.
     * @param signingCert the cert to verify signingKey's signature with.
     * @param msg the raw message data
     * @return a CMSSignedData holding the SignedData created.
     */
    public static byte[] createSignedDataStreaming(
        PrivateKey signingKey, X509CertificateHolder signingCert, byte[] msg)
        throws CMSException, OperatorCreationException, IOException
    {
        SignerInfoGenerator signerInfoGenerator =
                    new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withECDSA", signingKey, signingCert);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(signerInfoGenerator);

        Store<X509CertificateHolder> certs =
            new CollectionStore<X509CertificateHolder>(
                            Collections.singletonList(signingCert));

        gen.addCertificates(certs);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream sOut = gen.open(bOut, true);

        sOut.write(msg);

        sOut.close();
        
        return bOut.toByteArray();
    }

    /**
     * Verify the passed in encoding of a CMS SignedData using the streaming API,
     * assumes encapsulated data.
     *
     * @param encodedSignedData the BER encoding of the SignedData
     */
    public static void verifySignedEncapsulatedStreaming(byte[] encodedSignedData)
        throws CMSException, OperatorCreationException,
               IOException, CertificateException
    {
        CMSSignedDataParser signedDataParser = new CMSSignedDataParser(
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(),
            new ByteArrayInputStream(encodedSignedData));

        signedDataParser.getSignedContent().drain();
        
        SignerInformationStore signers = signedDataParser.getSignerInfos();
        Store certs = signedDataParser.getCertificates();

        for (SignerInformation signerInfo : signers)
        {
            Collection<X509CertificateHolder> certCollection =
                                    certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();

            System.out.println("sig verified: " +
                signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder()
                                          .setProvider("BC").build(cert)));
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyPair selfSignedKp = generateECKeyPair();
        X509CertificateHolder selfSignedCert =
            createTrustAnchor(selfSignedKp, "SHA256withECDSA");

        byte[] encapSignedStream = createSignedDataStreaming(
                         selfSignedKp.getPrivate(), selfSignedCert,
                         msg);

        verifySignedEncapsulatedStreaming(encapSignedStream);

        CMSSignedDataParser signedDataParser = new CMSSignedDataParser(
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(),
            encapSignedStream);

        CMSTypedStream typedStream = signedDataParser.getSignedContent();

        InputStream data = typedStream.getContentStream();
        System.out.println(Strings.fromByteArray(Streams.readAll(data)));
    }
}
