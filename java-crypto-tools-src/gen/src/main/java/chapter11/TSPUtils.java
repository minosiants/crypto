package chapter11;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

public class TSPUtils
{
    /**
     * Create a simple TSP request for the passed in SHA-256 hash.
     *
     * @param data the data that we want timestamped.
     * @return a DER encoding of the resulting TSP request.
     */
    public static byte[] createTspRequest(byte[] data)
        throws IOException, NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        return reqGen.generate(TSPAlgorithms.SHA256,
                                        digest.digest(data)).getEncoded();
    }

    /**
     * Create a TSP request for the passed in SHA-256 hash which also
     * includes a nonce and, possibly, a request for certificates.
     *
     * @param data the data we want time-stamped.
     * @param nonce a nonce associated with this request.
     * @param requestTsaCert if true, authority should send back a
     *                       copy of its certificate.
     * @return a DER encoding of the resulting TSP request.
     */
    public static byte[] createNoncedTspRequest(
        byte[] data, BigInteger nonce, boolean requestTsaCert)
        throws IOException, NoSuchAlgorithmException
    {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        reqGen.setCertReq(requestTsaCert);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        return reqGen.generate(
                 TSPAlgorithms.SHA256, digest.digest(data), nonce).getEncoded();
    }

    /**
     * Create a TSP response for the passed in byte encoded TSP request.
     *
     * @param tsaSigningKey  TSA signing key.
     * @param tsaSigningCert copy of TSA verification certificate.
     * @param serialNumber   response serial number
     * @param tsaPolicy      time stamp
     * @param encRequest     byte encoding of the TSP request.
     */
    public static byte[] createTspResponse(
        PrivateKey tsaSigningKey, X509Certificate tsaSigningCert,
        BigInteger serialNumber, ASN1ObjectIdentifier tsaPolicy, byte[] encRequest)
        throws TSPException, OperatorCreationException,
        GeneralSecurityException, IOException
    {
        AlgorithmIdentifier digestAlgorithm =
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        DigestCalculatorProvider digProvider =
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        TimeStampRequest tspRequest = new TimeStampRequest(encRequest);

        SignerInfoGenerator tsaSigner = new JcaSimpleSignerInfoGeneratorBuilder()
            .build("SHA256withECDSA", tsaSigningKey, tsaSigningCert);
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            tsaSigner, digProvider.get(digestAlgorithm), tsaPolicy);

        // client has requested a copy of the signing certificate
        if (tspRequest.getCertReq())
        {
            tsTokenGen.addCertificates(
                new JcaCertStore(Collections.singleton(tsaSigningCert)));
        }

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(
            tsTokenGen, TSPAlgorithms.ALLOWED);

        return tsRespGen.generate(tspRequest, serialNumber, new Date()).getEncoded();
    }

    /**
     * Verify that the passed in response can be verified by the TSA certificate and is
     * appropriate to the time-stamp request encoded in encRequest.
     *
     * @param encResponse an ASN.1 binary encoding of a time-stamp response.
     * @param tsaCertificate the certificate for the TSA that generated the response.
     * @param encRequest an ASN.1 binary encoding of the originating request.
     * @return true if the response can be verified, an exception is thrown if
     * validation fails.
     */
    public static boolean verifyTspResponse(
        byte[] encResponse,
        X509Certificate tsaCertificate,
        byte[] encRequest)
        throws IOException, TSPException, OperatorCreationException
    {
        TimeStampResponse tspResp = new TimeStampResponse(encResponse);

        // response/request validate will throw an exception if there is an issue
        tspResp.validate(new TimeStampRequest(encRequest));

        TimeStampToken tsToken = tspResp.getTimeStampToken();

        // token signature validate will throw an exception if there is an issue
        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder()
            .setProvider("BC")
            .build(tsaCertificate));

        return true;
    }

    /**
     * Create a TSP request for the first SignerInfo in a SignedData structure.
     *
     * @param nonce nonce to use with the request.
     * @param encSignedData the encoding of the SignedData structure.
     * @return a TSP request.
     */
    public static byte[] createSignerInfoTspRequest(
        BigInteger nonce,
        byte[] encSignedData)
        throws GeneralSecurityException,
               CMSException, IOException
    {
        CMSSignedData signedData = new CMSSignedData(encSignedData);
        SignerInformation signer = signedData.getSignerInfos().iterator().next();

        return createNoncedTspRequest(signer.getSignature(), nonce, true);
    }

    /**
     * Create a CMS attribute for carrying a TSP response.
     *
     * @param tspResponse response from the time-stamp authority we want to reference.
     * @return a suitable attribute for a TSP response.
     */
    public static Attribute createTspAttribute(byte[] tspResponse)
        throws TSPException, IOException
    {
        TimeStampResponse response = new TimeStampResponse(tspResponse);
        TimeStampToken timestampToken = response.getTimeStampToken();

        return new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                       new DERSet(timestampToken.toCMSSignedData().toASN1Structure()));
    }

    /**
     * Replace the SignerInformation in the CMS SignedData represented by
     * encSignedData with a time-stamped version.
     *
     * @param encSignedData encoding of the SignedData to be time-stamped.
     * @param nonce nonce for the TSP request.
     * @param tsaSigningKey time-stamp authority signing key.
     * @param tsaSigningCert time-stamp authority certificate.
     * @param serialNumber serial number for time-stamp response
     * @param tsaPolicyOID policy under which time-stamp authority is working.
     * @return encoding of a new version of encSignedData with a time-stamp.
     */
    public static byte[] createTimeStampedSignedData(
        byte[] encSignedData,
        BigInteger nonce,
        PrivateKey tsaSigningKey, X509Certificate tsaSigningCert,
        BigInteger serialNumber, ASN1ObjectIdentifier tsaPolicyOID)
        throws OperatorCreationException,
               GeneralSecurityException,
               CMSException, TSPException, IOException
    {
        CMSSignedData signedData = new CMSSignedData(encSignedData);
        SignerInformation signer = signedData.getSignerInfos().iterator().next();

        byte[] tspReq = createSignerInfoTspRequest(nonce, encSignedData);

        byte[] tspResp = createTspResponse(tsaSigningKey, tsaSigningCert,
                                            serialNumber, tsaPolicyOID, tspReq);

        // check the response
        verifyTspResponse(tspResp, tsaSigningCert, tspReq);

        // set up attribute table with TSP attribute in it.
        ASN1EncodableVector timestampVector = new ASN1EncodableVector();

        timestampVector.add(createTspAttribute(tspResp));

        AttributeTable at = new AttributeTable(timestampVector);

        // create replacement signer
        signer = SignerInformation.replaceUnsignedAttributes(signer, at);

        // create replacement SignerStore
        SignerInformationStore newSignerStore = new SignerInformationStore(signer);

        // replace the signers in the signed data object
        return CMSSignedData.replaceSigners(signedData, newSignerStore).getEncoded();
    }

    /**
     * Verify the time-stamp token attribute on the passed in CMS SignedData.
     * Note: in this case we are using the certificate stored in the TimeStampToken
     * associated with the SignedData.
     *
     * @param cmsSignedData encoding of the CMS SignedData we want to check.
     * @return true if verifies, exception thrown otherwise.
     */
    public static boolean verifyTimeStampedSigner(byte[] cmsSignedData)
        throws CMSException,
               IOException, TSPException,
               CertificateException, OperatorCreationException
    {
        CMSSignedData signedData = new CMSSignedData(cmsSignedData);
        SignerInformation signer = signedData.getSignerInfos().iterator().next();

        TimeStampToken tspToken = new TimeStampToken(
            ContentInfo.getInstance(
                signer.getUnsignedAttributes()
                    .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
                        .getAttributeValues()[0]));

        Collection certCollection = tspToken.getCertificates()
                                        .getMatches(tspToken.getSID());
        Iterator certIt = certCollection.iterator();
        X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

        // this method throws an exception if validation fails.
        tspToken.validate(new JcaSimpleSignerInfoVerifierBuilder()
                                    .setProvider("BC").build(cert));

        return true;
    }
}
