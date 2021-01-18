package chapter11;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.Iterator;
import java.util.regex.PatternSyntaxException;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter6.RsaUtils.generateRSAKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class EnvelopedDataExample
{
    /**
     * Add a KeyTransRecipientInfo to the passed in enveloped-data generator.
     *
     * @param envGen the generator to add the KeyTransRecipientInfo to.
     * @param encryptionCert the public key certificate for the targeted recipient.
     */
    public static void addKeyTransRecipient(
            CMSEnvelopedGenerator envGen,
            X509Certificate encryptionCert)
    throws GeneralSecurityException
    {
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
    }

    /**
     * Add a KeyTransRecipientInfo to the passed in enveloped-data generator
     * using a keyIdentifier rather than a certificate.
     *
     * @param envGen the generator to add the KeyTransRecipientInfo to.
     * @param keyIdentifier the identifier for the public key.
     * @param wrappingKey the public key for the targeted recipient.
     */
    public static void addKeyTransRecipient(
            CMSEnvelopedGenerator envGen,
            byte[] keyIdentifier,
            PublicKey wrappingKey)
    throws GeneralSecurityException
    {
        JcaAlgorithmParametersConverter paramsConverter =
                                            new JcaAlgorithmParametersConverter();

        AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSAES_OAEP,
            new OAEPParameterSpec("SHA-256",
                "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT));

        envGen.addRecipientInfoGenerator(
            new JceKeyTransRecipientInfoGenerator(
                keyIdentifier,
                oaepParams,
                wrappingKey).setProvider("BC"));
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData
     * structure by using the recipient matching the passed in parameters.
     *
     * @param encEnvelopedData the BER encoded EnvelopedData structure.
     * @param privateKey the recipient private key (for key transport).
     * @param encryptionCert the recipient's corresponding public key certificate.
     * @return the original data that was enveloped as a byte[].
     */
    public static byte[] extractUsingKeyTransRecipient(
        byte[] encEnvelopedData,
        PrivateKey privateKey, X509Certificate encryptionCert)
        throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientInformation recipient = recipients.get(
                                    new JceKeyTransRecipientId(encryptionCert));

        if (recipient != null)
        {
            return recipient.getContent(
                    new JceKeyTransEnvelopedRecipient(privateKey)
                        .setProvider("BC"));
        }

        throw new IllegalArgumentException("recipient for certificate not found");
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData
     * structure by using the recipient matching the passed in parameters
     * and the CMS streaming model.
     *
     * @param encEnvelopedData the BER encoded EnvelopedData structure.
     * @param privateKey the recipient private key (for key transport).
     * @param encryptionCert the recipient's corresponding public key certificate.
     * @return the original data that was enveloped as a byte[].
     */
    public static CMSTypedStream streamExtractUsingKeyTransRecipient(
        byte[] encEnvelopedData,
        PrivateKey privateKey, X509Certificate encryptionCert)
        throws CMSException, IOException
    {
        CMSEnvelopedDataParser envelopedData
                                 = new CMSEnvelopedDataParser(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientInformation recipient = recipients.get(
                                    new JceKeyTransRecipientId(encryptionCert));

        if (recipient != null)
        {
            return recipient.getContentStream(
                    new JceKeyTransEnvelopedRecipient(privateKey)
                        .setProvider("BC"));
        }

        throw new IllegalArgumentException("recipient for certificate not found");
    }

    /**
     * Add a KeyAgreeRecipientInfo to the passed in enveloped-data generator.
     *
     * @param envGen the generator to add the KeyAgreeRecipientInfo to.
     * @param initiatorKey the private key for the enveloped-data originator.
     * @param initiatorCert the public key certificate for the originator.
     * @param recipientCert the public key certificate for the targeted recipient.
     */
    public static void addKeyAgreeRecipient(
        CMSEnvelopedGenerator envGen,
        PrivateKey initiatorKey, X509Certificate initiatorCert,
        X509Certificate recipientCert)
    throws GeneralSecurityException
    {
        envGen.addRecipientInfoGenerator(
            new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECCDH_SHA384KDF,
                initiatorKey,
                initiatorCert.getPublicKey(),
                CMSAlgorithm.AES256_WRAP)
                .addRecipient(recipientCert).setProvider("BC"));
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData
     * structure by using the recipient matching the passed in parameters.
     *
     * @param encEnvelopedData the BER encoded EnvelopedData structure.
     * @param recipientKey the recipient private key (for agreement).
     * @param recipientCert the recipient's corresponding public key certificate.
     * @return the original data that was enveloped as a byte[].
     */
    public static byte[] extractUsingKeyAgreeRecipient(
        byte[] encEnvelopedData,
        PrivateKey recipientKey, X509Certificate recipientCert)
    throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new JceKeyAgreeRecipientId(recipientCert);
        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
            new JceKeyAgreeEnvelopedRecipient(recipientKey).setProvider("BC"));
    }

    /**
     * Add a PasswordRecipientInfo to the passed in enveloped-data generator.
     *
     * @param envGen the generator to add the PasswordRecipientInfo to.
     * @param passwd the password to use as the basis of the PBE key.
     * @param salt the salt to use to generate the PBE key.
     * @param iterationCount the iterationCount to use to generate the PBE key.
     */
    public static void addPasswordRecipient(
        CMSEnvelopedGenerator envGen,
        char[] passwd,
        byte[] salt,
        int iterationCount)
    {
        envGen.addRecipientInfoGenerator(
            new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC, passwd)
                .setProvider("BC")
                .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8)
                .setPRF(PasswordRecipient.PRF.HMacSHA384)
                .setSaltAndIterationCount(salt, iterationCount));
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData
     * structure by using the recipient matching the passed in parameters.
     *
     * @param encEnvelopedData the BER encoded EnvelopedData structure.
     * @param passwd the password to use as the source of the PBE key.
     * @return the original data that was enveloped as a byte[].
     */
    public static byte[] extractUsingPasswordRecipient(
        byte[] encEnvelopedData,
        char[] passwd)
        throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new PasswordRecipientId();
        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
            new JcePasswordEnvelopedRecipient(passwd)
                .setProvider("BC")
                .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8));
    }

    /**
     * Add a KEKRecipientInfo to the passed in enveloped-data generator.
     *
     * @param envGen the generator to add the KEKRecipientInfo to.
     * @param keyID the keyID to store for the recipient to match.
     * @param wrappingKey the wrapping key corresponding to the keyID.
     */
    public static void addKEKRecipient(
        CMSEnvelopedGenerator envGen,
        byte[] keyID, SecretKey wrappingKey)
    {
        envGen.addRecipientInfoGenerator(
            new JceKEKRecipientInfoGenerator(keyID, wrappingKey)
                .setProvider("BC"));
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData
     * structure by using the recipient matching the passed in parameters.
     *
     * @param encEnvelopedData the BER encoded EnvelopedData structure.
     * @param keyID the keyID matching the recipient.
     * @param wrappingKey the wrapping key corresponding to the keyID.
     * @return the original data that was enveloped as a byte[].
     */
    public static byte[] extractUsingKEKRecipient(
        byte[] encEnvelopedData,
        byte[] keyID, SecretKey wrappingKey)
        throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new KEKRecipientId(keyID);
        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
            new JceKEKEnvelopedRecipient(wrappingKey)
                .setProvider("BC"));
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        JcaX509CertificateConverter converter =
            new JcaX509CertificateConverter().setProvider("BC");

        byte[] msg = Strings.toByteArray("Hello, world!");

        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();

        KeyPair recipientRsaKp = generateRSAKeyPair();
        X509Certificate recipientRsaCert = converter.getCertificate(
            createTrustAnchor(recipientRsaKp, "SHA256withRSA"));

        addKeyTransRecipient(envGen, recipientRsaCert);

        KeyPair originatorEcKp = generateECKeyPair();
        X509Certificate originatorEcCert = converter.getCertificate(
            createTrustAnchor(originatorEcKp, "SHA256withECDSA"));

        KeyPair recipientEcKp = generateECKeyPair();
        X509Certificate recipientEcCert = converter.getCertificate(
            createTrustAnchor(recipientEcKp, "SHA256withECDSA"));

        addKeyAgreeRecipient(envGen,
                 originatorEcKp.getPrivate(), originatorEcCert, recipientEcCert);

        byte[] keyID = Strings.toByteArray("KeyID");
        SecretKey wrappingKey = new SecretKeySpec(
                        Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        addKEKRecipient(envGen, keyID, wrappingKey);

        char[] passwd = "password".toCharArray();

        addPasswordRecipient(envGen, passwd, Strings.toByteArray("Salt"), 2048);

        CMSEnvelopedData envData = envGen.generate(
            new CMSProcessableByteArray(msg),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider("BC")
                .build());

        byte[] envEnc = envData.getEncoded();

        byte[] keyTransRecovered = extractUsingKeyTransRecipient(
            envEnc, recipientRsaKp.getPrivate(), recipientRsaCert);

        System.err.println(Strings.fromByteArray(keyTransRecovered));

        byte[] keyAgreeRecovered = extractUsingKeyAgreeRecipient(
            envEnc, recipientEcKp.getPrivate(), recipientEcCert);

        System.err.println(Strings.fromByteArray(keyAgreeRecovered));

        byte[] kekRecovered = extractUsingKEKRecipient(envEnc, keyID, wrappingKey);

        System.err.println(Strings.fromByteArray(kekRecovered));

        byte[] passwordRecovered = extractUsingPasswordRecipient(envEnc, passwd);

        System.err.println(Strings.fromByteArray(passwordRecovered));

        CMSEnvelopedDataStreamGenerator envStreamGen =
                                           new CMSEnvelopedDataStreamGenerator();

        addKeyTransRecipient(envStreamGen, recipientRsaCert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = envStreamGen.open(
            bOut,
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider("BC")
                .build());

        out.write(msg);

        out.close();

        envEnc = bOut.toByteArray();

        CMSTypedStream cmsContent = streamExtractUsingKeyTransRecipient(
            envEnc, recipientRsaKp.getPrivate(), recipientRsaCert);

        System.err.println(Strings.fromByteArray(
                               Streams.readAll(cmsContent.getContentStream())));
    }
}
