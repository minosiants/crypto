package chapter9;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static chapter8.JcaX509Certificate.calculateDate;

public class JcaX509CRL
{
    public static X509CRLHolder createEmptyCRL(
        PrivateKey caKey,
        String sigAlg,
        X509CertificateHolder caCert)
        throws IOException, GeneralSecurityException, OperatorCreationException
    {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(),
                calculateDate(0));

        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);

        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                    .setProvider("BC").build(caKey);

        return crlGen.build(signer);
    }

    /**
     * Simple method to convert an X509CRLHolder to an X509CRL
     * using the java.security.cert.CertificateFactory class.
     */
    public static X509CRL convertX509CRLHolder(
                                             X509CertificateHolder crlHolder)
            throws GeneralSecurityException, IOException
    {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");

        return (X509CRL)cFact.generateCRL(
                                           new ByteArrayInputStream(
                                                   crlHolder.getEncoded()));
    }


    /**
     * Create a CRL containing a single revocation.
     *
     * @param caKey the private key signing the CRL.
     * @param sigAlg the signature algorithm to sign the CRL with.
     * @param caCert the certificate associated with the key signing the CRL.
     * @param certToRevoke the certificate to be revoked.
     * @return an X509CRLHolder representing the revocation list for the CA.
     */
    public X509CRLHolder createCRL(
            PrivateKey caKey,
            String sigAlg,
            X509CertificateHolder caCert,
            X509CertificateHolder certToRevoke)
            throws IOException, GeneralSecurityException, OperatorCreationException
    {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(),
                calculateDate(0));

        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);


        crlGen.addCRLEntry(certToRevoke.getSerialNumber(),
                                            new Date(), extGen.generate());

        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                    .setProvider("BC").build(caKey);

        return crlGen.build(signer);
    }
    /**
     * Create an updated CRL from a previous one and add a new revocation.
     *
     * @param caKey the private key signing the CRL.
     * @param sigAlg the signature algorithm to sign the CRL with.
     * @param caCert the certificate associated with the key signing the CRL.
     * @param previousCaCRL the previous CRL for this CA.
     * @param certToRevoke the certificate to be revoked.
     * @return an X509CRLHolder representing the updated revocation list for the
     * CA.
     */
    public X509CRLHolder updateCRL(
            PrivateKey caKey,
            String sigAlg,
            X509CertificateHolder caCert,
            X509CRLHolder previousCaCRL,
            X509CertificateHolder certToRevoke)
            throws IOException, GeneralSecurityException, OperatorCreationException
    {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getIssuer(),
                calculateDate(0));

        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add new revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);

        crlGen.addCRLEntry(certToRevoke.getSerialNumber(),
                                            new Date(), extGen.generate());

        // add previous revocations
        crlGen.addCRL(previousCaCRL);

        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                    .setProvider("BC").build(caKey);

        return crlGen.build(signer);
    }
}
