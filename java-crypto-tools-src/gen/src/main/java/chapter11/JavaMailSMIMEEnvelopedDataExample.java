package chapter11;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Strings;

import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class JavaMailSMIMEEnvelopedDataExample
{
    /**
     * Create an application/pkcs7-mime from the body part in message.
     *
     * @param encryptionCert public key certificate associated with the
     *                       intended recipient.
     * @param message byte[] representing the body part to be encrypted.
     * @return a MimeBodyPart containing a application/pkcs7-mime MIME object.
     */
    public static MimeBodyPart createEnveloped(
        X509Certificate encryptionCert,
        MimeBodyPart message)
        throws GeneralSecurityException, CMSException, SMIMEException
    {
        SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

        JcaAlgorithmParametersConverter paramsConverter =
                                         new JcaAlgorithmParametersConverter();

        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSAES_OAEP,
            new OAEPParameterSpec("SHA-256",
                "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT));

        envGen.addRecipientInfoGenerator(
            new JceKeyTransRecipientInfoGenerator(
                encryptionCert, oaepParams).setProvider("BC"));

        return envGen.generate(message,
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider("BC")
                        .build());
    }

    /**
     * Extract a MIME body part from an enveloped message.
     *
     * @param encryptedMessage the enveloped message.
     * @param recipientCert the certificate associated with the recipient key.
     * @param recipientKey the private key to recover the body part with.
     */
    public static MimeBodyPart decryptEnveloped(
        MimeBodyPart encryptedMessage,
        X509Certificate recipientCert,
        PrivateKey recipientKey)
        throws
        CMSException, MessagingException, SMIMEException
    {
        SMIMEEnveloped envData = new SMIMEEnveloped(encryptedMessage);

        RecipientInformationStore recipients = envData.getRecipientInfos();

        RecipientInformation recipient = recipients.get(
            new JceKeyTransRecipientId(recipientCert));

        return SMIMEUtil.toMimeBodyPart(recipient.getContent(
            new JceKeyTransEnvelopedRecipient(recipientKey).setProvider("BC")));
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

        MimeBodyPart signedMM = createEnveloped(
            selfSignedCert, new MimeBodyPart(new ByteArrayInputStream(bodyPart)));

        BodyPart decPart = decryptEnveloped(
                              signedMM, selfSignedCert, selfSignedKp.getPrivate());
        
        System.out.println(decPart.getContent());
    }
}
