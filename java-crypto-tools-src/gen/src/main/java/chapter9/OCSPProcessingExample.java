package chapter9;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import static chapter8.JcaX509Certificate.createIntermediateCertificate;
import static chapter8.JcaX509Certificate.createTrustAnchor;


/**
 * Example of OCSP request/response generation.
 */
public class OCSPProcessingExample
{
    /**
     * Generation of an OCSP request concerning certificate serialNumber from
     * issuer represented by issuerCert with a nonce extension.
     *
     * @param issuerCert certificate of issuer of certificate we want to check.
     * @param serialNumber serial number of the certificate we want to check.
     * @return an OCSP request.
     */
    public static OCSPReq generateOCSPRequest(
                    X509CertificateHolder issuerCert, BigInteger serialNumber)
        throws OCSPException, OperatorCreationException
    {
        DigestCalculatorProvider digCalcProv =
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        // Generate the id for the certificate we are looking for
        CertificateID   id = new CertificateID(
            digCalcProv.get(CertificateID.HASH_SHA1), issuerCert, serialNumber);

        // Basic request generation with nonce
        OCSPReqBuilder bldr = new OCSPReqBuilder();

        bldr.addRequest(id);

        // Create details for nonce extension - example only!
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

        bldr.setRequestExtensions(new Extensions(
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                         true, new DEROctetString(nonce.toByteArray()))));

        return bldr.build();
    }
    /**
     * Generation of an OCSP response based on a single revoked certificate.
     *
     * @param request the OCSP request we are asked to check.
     * @param responderKey signing key for the responder.
     * @param pubKey public key for responder.
     * @param revokedSerialNumber the serial number that we regard as revoked.
     * @return an OCSP response.
     */
    public static OCSPResp generateOCSPResponse(
        OCSPReq request,
        PrivateKey responderKey, SubjectPublicKeyInfo pubKey,
        BigInteger revokedSerialNumber)
        throws OCSPException, OperatorCreationException
    {
        DigestCalculatorProvider digCalcProv =
             new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        BasicOCSPRespBuilder basicRespBldr = new BasicOCSPRespBuilder(
                                     pubKey,
                                     digCalcProv.get(CertificateID.HASH_SHA1));

        Extension ext = request.getExtension(
                                  OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        if (ext != null)
        {
            basicRespBldr.setResponseExtensions(new Extensions(ext));
        }
        
        Req[] requests = request.getRequestList();
        
        for (int i = 0; i != requests.length; i++)
        {
            CertificateID certID = requests[i].getCertID();
            
            // this would normally be a lot more general!
            if (certID.getSerialNumber().equals(revokedSerialNumber))
            {
                basicRespBldr.addResponse(certID,
                    new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn));
            }
            else
            {
                basicRespBldr.addResponse(certID, CertificateStatus.GOOD);
            }
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                                        .setProvider("BC").build(responderKey);

        BasicOCSPResp basicResp = basicRespBldr.build(signer, null, new Date());
        
        OCSPRespBuilder respBldr = new OCSPRespBuilder();
        
        return respBldr.build(OCSPRespBuilder.SUCCESSFUL, basicResp);
    }
    /**
     * Check a certificate against a revoked serial number by using an
     * OCSP request and response.
     *
     * @param caPrivKey the issuer private key.
     * @param caCert the issuer certificate.
     * @param revokedSerialNumber a serial number the responder is to
     *                            treat as revoked.
     * @param certToCheck the certificate to generate the OCSP request for.
     * @return a status message for certToCheck
     */
    public static String getStatusMessage(
        PrivateKey caPrivKey, X509CertificateHolder caCert,
              BigInteger revokedSerialNumber, X509CertificateHolder certToCheck)
        throws Exception
    {
        OCSPReq request = generateOCSPRequest(
                                        caCert, certToCheck.getSerialNumber());

        OCSPResp response = generateOCSPResponse(
            request,
            caPrivKey, caCert.getSubjectPublicKeyInfo(),
            revokedSerialNumber);
        
        BasicOCSPResp   basicResponse =
                            (BasicOCSPResp)response.getResponseObject();

        ContentVerifierProvider verifier =
              new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(caCert.getSubjectPublicKeyInfo());

        // verify the response
        if (basicResponse.isSignatureValid(verifier))
        {
            SingleResp[]      responses = basicResponse.getResponses();

            Extension reqNonceExt = request.getExtension(
                             OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            byte[] reqNonce = reqNonceExt.getEncoded();
            Extension respNonceExt = basicResponse.getExtension(
                         OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

            // validate the nonce if it is present
            if (respNonceExt != null
                && Arrays.equals(reqNonce, respNonceExt.getEncoded()))
            {
                String message = "";
                for (int i = 0; i != responses.length; i++)
                {
                    message += " certificate number "
                        + responses[i].getCertID().getSerialNumber();
                    if (responses[i].getCertStatus()
                        == CertificateStatus.GOOD)
                    {
                        return message + " status: good";
                    }
                    else
                    {
                        return message + " status: revoked";
                    }
                }

                return message;
            }
            else
            {
                return "response nonce failed to validate";
            }
        }
        else
        {
            return "response failed to verify";
        }
    }
    public static void main(
        String[] args)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        KeyPair caKp = kpGen.generateKeyPair();

        X509CertificateHolder caCert =
                           createTrustAnchor(caKp, "SHA256withECDSA");

        KeyPair certKp = kpGen.generateKeyPair();

        X509CertificateHolder certOfInterest = createIntermediateCertificate(
                                        caCert,
                                        caKp.getPrivate(),"SHA256withECDSA",
                                        certKp.getPublic(), 0);

        System.out.println(
            getStatusMessage(
                caKp.getPrivate(), caCert,
                certOfInterest.getSerialNumber().add(BigInteger.ONE),
                certOfInterest));
    }
}
