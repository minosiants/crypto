package chapter11;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

import static chapter11.SMIMESignedDataExample.generateSMIMECapabilities;
import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class JavaMailSMIMESignedDataExample
{
    /**
     * Create a multipart/signed for the body part in message.
     *
     * @param signingKey private key to generate the signature with.
     * @param signingCert public key certificate associated with the signing key.
     * @param message the body part to be signed.
     * @return a MimeMultipart of the type multipart/signed MIME object.
     */
    public static MimeMultipart createSignedMultipart(
        PrivateKey signingKey,
        X509CertificateHolder signingCert,
        MimeBodyPart message)
        throws OperatorCreationException, SMIMEException
    {
        List<X509CertificateHolder> certList = new ArrayList<>();
        certList.add(signingCert);
        Store<X509CertificateHolder> certs = new CollectionStore<>(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .setSignedAttributeGenerator(generateSMIMECapabilities())
                .build("SHA256withECDSA", signingKey, signingCert));
        gen.addCertificates(certs);

        return gen.generate(message);
    }

    /**
     * Verify a MimeMultipart containing a multipart/signed object.
     *
     * @param signedMessage the multipart/signed.
     * @param signerCert the certificate of one of the signers of signedMessage.
     * @return true if the multipart/signed verified for signerCert, false otherwise.
     */
    public static boolean verifySignedMultipart(
        MimeMultipart signedMessage,
        X509CertificateHolder signerCert)
        throws GeneralSecurityException, OperatorCreationException,
               CMSException, MessagingException
    {
        SMIMESigned signedData = new SMIMESigned(signedMessage);

        SignerInformationStore signers = signedData.getSignerInfos();

        SignerInformation signer = signers.get(
            new SignerId(signerCert.getIssuer(),
                             signerCert.getSerialNumber()));

        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                                   .setProvider("BC").build(signerCert));
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

        MimeMultipart signedMM = createSignedMultipart(selfSignedKp.getPrivate(),
            selfSignedCert, new MimeBodyPart(new ByteArrayInputStream(bodyPart)));

        System.out.println("verified: "+ verifySignedMultipart(
                       signedMM, selfSignedCert));
        System.out.println(signedMM.getBodyPart(0).getContent());
    }
}
