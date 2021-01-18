package chapter11;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMIMESignedWriter;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class SMIMESignedDataExample
{
    /**
     * Basic method to provide some S/MIME capability attributes for anyone
     * responding to our message.
     *
     * @return an AttributeTable with the additional attributes.
     */
    public static AttributeTable generateSMIMECapabilities()
    {
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();

        SMIMECapabilityVector caps = new SMIMECapabilityVector();
        caps.addCapability(SMIMECapability.aES128_CBC);
        caps.addCapability(SMIMECapability.aES192_CBC);
        caps.addCapability(SMIMECapability.aES256_CBC);
        caps.addCapability(SMIMECapability.preferSignedData);
        
        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        return new AttributeTable(signedAttrs);
    }

    /**
     * Create a multipart/signed for the body part in message.
     *
     * @param signingKey private key to generate the signature with.
     * @param signingCert public key certificate associated with the signing key.
     * @param message byte[] representing the body part to be signed.
     * @return a byte[] containing a multipart/signed MIME object.
     */
    public static byte[] createSignedMultipart(
        PrivateKey signingKey,
        X509CertificateHolder signingCert,
        byte[] message)
        throws OperatorCreationException, CMSException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMESignedWriter.Builder sigBldr = new SMIMESignedWriter.Builder();

        sigBldr.addCertificate(signingCert);

        sigBldr.addSignerInfoGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder()
                     .setProvider("BC")
                     .setSignedAttributeGenerator(generateSMIMECapabilities())
                     .build("SHA256withECDSA", signingKey, signingCert));

        SMIMESignedWriter sigWrt = sigBldr.build(bOut);

        OutputStream out = sigWrt.getContentStream();

        out.write(message);

        out.close();

        return bOut.toByteArray();
    }

    /**
     * Verify the signerInfo associated with signerCert, writing the content to
     * contentStream as we go.
     *
     * @param multiPart input stream containing the signed multiPart to examine.
     * @param signerCert a certificate associated with a private key that signed
     *                  the content.
     * @param contentStream output stream to receive the signed content.
     * @return true if the signed multipart verified for signerCert, false otherwise.
     */
    public static boolean verifySignedMultipart(
        InputStream multiPart,
        X509CertificateHolder signerCert,
        OutputStream contentStream)
        throws IOException
    {
        AtomicBoolean isVerified = new AtomicBoolean(false);

        MimeParserProvider provider = new SMimeParserProvider("7bit",
                                              new BcDigestCalculatorProvider());

        MimeParser parser = provider.createParser(multiPart);

        parser.parse(new SMimeParserListener()
        {
            public void content(
                MimeParserContext parserContext,
                Headers headers,
                InputStream inputStream)
                throws IOException
            {
                byte[] content = Streams.readAll(inputStream);

                contentStream.write(content);
            }

            public void signedData(
                MimeParserContext parserContext,
                Headers headers,
                Store certificates, Store CRLs, Store attributeCertificates,
                SignerInformationStore signers)
                throws CMSException
            {
                SignerInformation signerInfo = signers.get(
                    new SignerId(
                            signerCert.getIssuer(), signerCert.getSerialNumber()));

                try
                {
                    isVerified.set(signerInfo.verify(
                        new JcaSimpleSignerInfoVerifierBuilder()
                               .setProvider("BC").build(signerCert)));
                }
                catch (Exception e)
                {
                    throw new CMSException(
                        "unable to process signerInfo: " + e.getMessage(), e);
                }
            }
        });

        return isVerified.get();
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        byte[] bodyPart = Strings.toByteArray(
               "Content-Type: text/plain; name=null; charset=us-ascii\r\n" +
                   "Content-Transfer-Encoding: 7bit\r\n" +
                   "Content-Disposition: inline; filename=test.txt\r\n" +
                   "\r\n" +
                   "Hello, world!\r\n");
        KeyPair selfSignedKp = generateECKeyPair();
        X509CertificateHolder selfSignedCert =
            createTrustAnchor(selfSignedKp, "SHA256withECDSA");

        byte[] data = createSignedMultipart(
                         selfSignedKp.getPrivate(), selfSignedCert, bodyPart);

        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        
        System.out.println("verified: "+ verifySignedMultipart(
                       new ByteArrayInputStream(data), selfSignedCert, contentStream));
        System.out.println(Strings.fromByteArray(contentStream.toByteArray()));
    }
}
