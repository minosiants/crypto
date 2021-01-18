package chapter12;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CRMFUtils
{
    /**
     * Basic example for generating a CRMF certificate request with POP for
     * an signing algorithm like DSA or a key pair for signature generation
     * from an algorithm like RSA.
     *
     * @param kp key pair whose public key we are making the request for.
     * @param subject subject principal to be associated with the certificate.
     * @param certReqID identity (for the client) of this certificate request.
     */
    public static byte[] generateRequestWithPOPSig(
        KeyPair kp, X500Principal subject, BigInteger certReqID)
        throws CRMFException, IOException, OperatorCreationException
    {
        JcaCertificateRequestMessageBuilder certReqBuild
            = new JcaCertificateRequestMessageBuilder(certReqID);

        certReqBuild
            .setPublicKey(kp.getPublic())
            .setSubject(subject)
            .setProofOfPossessionSigningKeySigner(
                new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(kp.getPrivate()));

        return certReqBuild.build().getEncoded();
    }
    /**
     * Authenticating example for generating a CRMF certificate request with POP
     * for a signing algorithm. In this case the CA will verify the subject from
     * the MAC validation.
     *
     * @param kp key pair whose public key we are making the request for.
     * @param certReqID identity (for the client) of this certificate request.
     * @param reqPassword authorising password for this request.
     */
    public static byte[] generateRequestWithPOPSig(
        KeyPair kp, BigInteger certReqID, char[] reqPassword)
        throws CRMFException, IOException, OperatorCreationException
    {
        JcaCertificateRequestMessageBuilder certReqBuild
            = new JcaCertificateRequestMessageBuilder(certReqID);

        certReqBuild
            .setPublicKey(kp.getPublic())
            .setAuthInfoPKMAC(
                new PKMACBuilder(
                    new JcePKMACValuesCalculator()),
                reqPassword)
            .setProofOfPossessionSigningKeySigner(
                new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(kp.getPrivate()));

        return certReqBuild.build().getEncoded();
    }
    /**
     * Basic example for generating a CRMF certificate request with POP for
     * an encryption only algorithm like ElGamal.
     *
     * @param kp key pair whose public key we are making the request for.
     * @param subject subject principal to be associated with the certificate.
     * @param certReqID identity (for the client) of this certificate request.
     */
    public static byte[] generateRequestWithPOPEnc(
        KeyPair kp, X500Principal subject, BigInteger certReqID)
        throws CRMFException, IOException
    {
        JcaCertificateRequestMessageBuilder certReqBuild
            = new JcaCertificateRequestMessageBuilder(certReqID);

        certReqBuild
            .setPublicKey(kp.getPublic())
            .setSubject(subject)
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        return certReqBuild.build().getEncoded();
    }
    /**
     * Basic example for generating a CRMF certificate request with POP for
     * a key agreement public key.
     *
     * @param kp key pair whose public key we are making the request for.
     * @param subject subject principal to be associated with the certificate.
     * @param certReqID identity (for the client) of this certificate request.
     */
    public static byte[] generateRequestWithPOPAgree(
        KeyPair kp, X500Principal subject, BigInteger certReqID)
        throws CRMFException, IOException
    {
        JcaCertificateRequestMessageBuilder certReqBuild
            = new JcaCertificateRequestMessageBuilder(certReqID);

        certReqBuild
            .setPublicKey(kp.getPublic())
            .setSubject(subject)
            .setProofOfPossessionSubsequentMessage(
                ProofOfPossession.TYPE_KEY_AGREEMENT, SubsequentMessage.encrCert);

        return certReqBuild.build().getEncoded();
    }
}
