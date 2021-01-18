package chapter11;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import chapter8.JcaX509Certificate;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.mime.smime.SMIMESignedWriter;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class SMIMEEnvelopedDataExample
{
    /**
     * Create an application/pkcs7-mime for the body part in message.
     *
     * @param encryptionCert public key certificate associated with the
     *                       intended recipient.
     * @param message byte[] representing the body part to be encrypted.
     * @return a byte[] containing a application/pkcs7-mime MIME object.
     */
    public static byte[] createEnveloped(
        X509Certificate encryptionCert,
        byte[] message)
        throws GeneralSecurityException, CMSException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMEEnvelopedWriter.Builder envBldr = new SMIMEEnvelopedWriter.Builder();

        JcaAlgorithmParametersConverter paramsConverter =
                                            new JcaAlgorithmParametersConverter();

        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSAES_OAEP,
            new OAEPParameterSpec("SHA-256",
                "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT));

        envBldr.addRecipientInfoGenerator(
            new JceKeyTransRecipientInfoGenerator(
                encryptionCert, oaepParams).setProvider("BC"));

        SMIMEEnvelopedWriter sigWrt = envBldr.build(bOut,
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider("BC")
                        .build());

        OutputStream out = sigWrt.getContentStream();

        out.write(message);

        out.close();

        return bOut.toByteArray();
    }

    /**
     * Decrypt the encrypted content in an application/pkcs7-mime message, writing
     * the content to contentStream as we go.
     *
     * @param encryptedPart input stream containing the enveloped Part to examine.
     * @param recipientCert a certificate associated with a private key that the
     *                      content was encrypted for.
     * @param recipientKey the private key that the content was encrypted for.
     * @param contentStream output stream to receive the decrypted content.
     */
    public static void decryptEnveloped(
        InputStream encryptedPart,
        X509Certificate recipientCert,
        PrivateKey recipientKey,
        OutputStream contentStream)
        throws IOException
    {
        MimeParserProvider provider = new SMimeParserProvider("7bit",
                                              new BcDigestCalculatorProvider());

        MimeParser parser = provider.createParser(encryptedPart);

        parser.parse(new SMimeParserListener()
        {
            public void envelopedData(
                MimeParserContext parserContext,
                Headers headers,
                OriginatorInformation originator,
                RecipientInformationStore recipients)
                throws IOException, CMSException
            {
                RecipientInformation recipInfo = recipients.get(
                                new JceKeyTransRecipientId(recipientCert));

                byte[] content = recipInfo.getContent(
                            new JceKeyTransEnvelopedRecipient(recipientKey));

                contentStream.write(content);
            }
        });

        contentStream.close();
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

        KeyPair selfSignedKp = generateRSAKeyPair();
        X509CertificateHolder selfSignedCertHldr =
            createTrustAnchor(selfSignedKp, "SHA256withRSA");

        X509Certificate selfSignedCert = new JcaX509CertificateConverter()
                            .setProvider("BC").getCertificate(selfSignedCertHldr);

        byte[] data = createEnveloped(
                         selfSignedCert, bodyPart);

        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        
        decryptEnveloped(
                       new ByteArrayInputStream(data),
                        selfSignedCert, selfSignedKp.getPrivate(),
                        contentStream);

        System.out.println(Strings.fromByteArray(contentStream.toByteArray()));
    }
}
