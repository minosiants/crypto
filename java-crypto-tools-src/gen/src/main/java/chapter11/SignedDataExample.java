package chapter11;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class SignedDataExample
{
    /**
     * Create a SignedData structure.
     *
     * @param signingKey the key to generate the signature with.
     * @param signingCert the cert to verify signingKey's signature with.
     * @param msg the raw message data
     * @param encapsulate true if the data being signed should wrapped.
     * @return a CMSSignedData holding the SignedData created.
     */
    public static CMSSignedData createSignedData(
        PrivateKey signingKey, X509CertificateHolder signingCert,
        byte[] msg, boolean encapsulate)
        throws CMSException, OperatorCreationException
    {
        ContentSigner contentSigner =
            new JcaContentSignerBuilder("SHA256withECDSA")
                      .setProvider("BC").build(signingKey);

        DigestCalculatorProvider digestCalcProvider =
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        SignerInfoGenerator signerInfoGenerator =
            new SignerInfoGeneratorBuilder(digestCalcProvider)
                        .build(contentSigner, signingCert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGenerator);

        Store<X509CertificateHolder> certs =
            new CollectionStore<X509CertificateHolder>(
                            Collections.singletonList(signingCert));

        gen.addCertificates(certs);

        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);

        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * Create a SignedData structure changing the signed attributes
     * it is created with from the default ones.
     *
     * @param signingKey the key to generate the signature with.
     * @param signingCert the cert to verify signingKey's signature with.
     * @param msg the raw message data
     * @param encapsulate true if the data being signed should wrapped.
     * @return a CMSSignedData holding the SignedData created.
     */
    public static CMSSignedData createSignedDataWithAttributesEdit(
        PrivateKey signingKey, X509CertificateHolder signingCert,
        byte[] msg, boolean encapsulate)
        throws CMSException, OperatorCreationException
    {
        ContentSigner contentSigner =
            new JcaContentSignerBuilder("SHA256withECDSA")
                      .setProvider("BC").build(signingKey);

        DigestCalculatorProvider digestCalcProvider =
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        SignerInfoGenerator signerInfoGenerator =
            new SignerInfoGeneratorBuilder(digestCalcProvider)
                .setSignedAttributeGenerator(new CMSAttributeTableGenerator()
                {
                    public AttributeTable getAttributes(Map parameters)
                        throws CMSAttributeTableGenerationException
                    {
                        AttributeTable table =
                            new DefaultSignedAttributeTableGenerator()
                                                .getAttributes(parameters);

                        return table.remove(CMSAttributes.cmsAlgorithmProtect);
                    }
                })
                .build(contentSigner, signingCert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGenerator);

        Store<X509CertificateHolder> certs =
            new CollectionStore<X509CertificateHolder>(
                            Collections.singletonList(signingCert));

        gen.addCertificates(certs);

        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);

        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * Create a SignedData structure using the JcaSimpleSignerInfoGeneratorBuilder.
     *
     * @param signingKey the key to generate the signature with.
     * @param signingCert the cert to verify signingKey's signature with.
     * @param msg the raw message data
     * @param encapsulate true if the data being signed should wrapped.
     * @return a CMSSignedData holding the SignedData created.
     */
    public static CMSSignedData createSignedDataSimple(
        PrivateKey signingKey, X509CertificateHolder signingCert,
        byte[] msg, boolean encapsulate)
        throws CMSException, OperatorCreationException
    {
        SignerInfoGenerator signerInfoGenerator =
            new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .build("SHA256withECDSA", signingKey, signingCert);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGenerator);

        Store<X509CertificateHolder> certs =
            new CollectionStore<X509CertificateHolder>(
                            Collections.singletonList(signingCert));

        gen.addCertificates(certs);

        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);

        return gen.generate(typedMsg, encapsulate);
    }

    /**
     * Update a SignerInfo to include a counter signature. The resulting
     * CMSSignedData will also contain the certificate for the counter signer.
     *
     * @param original the SignedData with the SignerInfo to be counter signed.
     * @param counterSignKey the key being used for counter signing.
     * @param counterSignCert the certificate associated with counterSignKey.
     * @return an updated SignedData with the counter signature.
     */
    public static CMSSignedData addCounterSignature(
        CMSSignedData original,
        PrivateKey counterSignKey, X509CertificateHolder counterSignCert)
        throws CMSException, OperatorCreationException
    {
        SignerInfoGenerator signerInfoGenerator =
            new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .build("SHA256withECDSA", counterSignKey, counterSignCert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGenerator);

        SignerInformationStore signers = original.getSignerInfos();
        SignerInformation signerInfo = signers.iterator().next();

        signerInfo = SignerInformation.addCounterSigners(
                            signerInfo, gen.generateCounterSigners(signerInfo));

        Collection originalCerts = original.getCertificates().getMatches(null);

        Set totalCerts = new HashSet();

        totalCerts.addAll(originalCerts);
        totalCerts.add(counterSignCert);

        CMSSignedData counterSigned = CMSSignedData.replaceSigners(
                                    original, new SignerInformationStore(signerInfo));

        counterSigned = CMSSignedData.replaceCertificatesAndCRLs(
                     counterSigned, new CollectionStore(totalCerts), null, null);

        return counterSigned;
    }

    /**
     * Verify the passed in encoding of a CMS SignedData, assumes encapsulated data.
     *
     * @param encodedSignedData the BER encoding of the SignedData
     */
    public static void verifySignedEncapsulated(byte[] encodedSignedData)
        throws CMSException, CertificateException, OperatorCreationException
    {
        CMSSignedData signedData = new CMSSignedData(encodedSignedData);
        SignerInformationStore signers = signedData.getSignerInfos();
        Store certs = signedData.getCertificates();

        for (SignerInformation signerInfo : signers)
        {
            Collection<X509CertificateHolder> certCollection =
                                       certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();

            System.out.println("sig verified: " +
                signerInfo.verify(
                        new JcaSimpleSignerInfoVerifierBuilder()
                                    .setProvider("BC").build(cert)));
        }
    }

    /**
     * Verify the passed in encoding of a CMS SignedData, assumes a detached
     * signature with msg representing the raw data that was signed.
     *
     * @param encodedSignedData the BER encoding of the SignedData
     * @param msg the data that was used to create the SignerInfo in the SignedData
     */
    public static void verifySignedDetached(byte[] encodedSignedData, byte[] msg)
        throws CMSException, CertificateException, OperatorCreationException
    {
        CMSSignedData signedData = new CMSSignedData(
                          new CMSProcessableByteArray(msg), encodedSignedData);

        SignerInformationStore signers = signedData.getSignerInfos();
        Store<X509CertificateHolder> certs = signedData.getCertificates();

        for (SignerInformation signerInfo : signers)
        {
            Collection<X509CertificateHolder> certCollection
                                     = certs.getMatches(signerInfo.getSID());
            X509CertificateHolder cert = certCollection.iterator().next();

            System.out.println("sig verified: " +
                signerInfo.verify(
                        new JcaSimpleSignerInfoVerifierBuilder()
                                    .setProvider("BC").build(cert)));
        }
    }

    /**
     * Verify all SignerInfos from a SignedData structure, including any
     * counter signatures.
     *
     * @param signedData BER encoding of the SignedData structure.
     */
    public static void verifyAllSigners(CMSSignedData signedData)
        throws CMSException
    {
        final Store<X509CertificateHolder> certs = signedData.getCertificates();

        System.out.println("signers verified: " + signedData.verifySignatures(
            new SignerInformationVerifierProvider()
            {
                public SignerInformationVerifier get(SignerId signerId)
                    throws OperatorCreationException
                {
                    try
                    {
                        X509CertificateHolder cert = (X509CertificateHolder)certs
                                        .getMatches(signerId).iterator().next();

                        return new JcaSimpleSignerInfoVerifierBuilder()
                                                  .setProvider("BC").build(cert);
                    }
                    catch (CertificateException e)
                    {
                        throw new OperatorCreationException(
                                 "verifier provider failed: " + e.getMessage(), e);
                    }
                }
            }));
    }

    public static void main(String[] args)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyPair selfSignedKp = generateECKeyPair();
        X509CertificateHolder selfSignedCert =
            createTrustAnchor(selfSignedKp, "SHA256withECDSA");

        CMSSignedData encapSigned = createSignedData(selfSignedKp.getPrivate(),
                                                selfSignedCert, msg, true);

        verifySignedEncapsulated(encapSigned.getEncoded());

        CMSTypedData cmsData = encapSigned.getSignedContent();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        cmsData.write(bOut);

        System.out.println(Strings.fromByteArray(bOut.toByteArray()));

        encapSigned = createSignedDataSimple(selfSignedKp.getPrivate(),
                                                selfSignedCert, msg, true);

        verifySignedEncapsulated(encapSigned.getEncoded());

        CMSSignedData detachSigned = createSignedData(selfSignedKp.getPrivate(),
                                               selfSignedCert, msg, false);

        verifySignedDetached(detachSigned.getEncoded(), msg);

        KeyPair counterKp = generateECKeyPair();
        X509CertificateHolder counterCert =
            createTrustAnchor(counterKp, "SHA256withECDSA");
        
        CMSSignedData counterSigned = addCounterSignature(encapSigned,
                                            counterKp.getPrivate(), counterCert);

        verifyAllSigners(counterSigned);
    }
}
