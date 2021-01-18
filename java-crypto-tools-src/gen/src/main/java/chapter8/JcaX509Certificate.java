package chapter8;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Example methods showing generation and verification of X.509 certificates
 */
public class JcaX509Certificate
{
    /**
     * Calculate a date in seconds (suitable for the PKIX profile - RFC 5280)
     *
     * @param hoursInFuture hours ahead of now, may be negative.
     * @return a Date set to now + (hoursInFuture * 60 * 60) seconds
     */
    public static Date calculateDate(int hoursInFuture)
    {
         long secs = System.currentTimeMillis() / 1000;

         return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }
    private static long serialNumberBase = System.currentTimeMillis();

    /**
     * Calculate a serial number using a monotonically increasing value.
     *
     * @return a BigInteger representing the next serial number in the sequence.
     */
    public static synchronized BigInteger calculateSerialNumber()
    {
        return BigInteger.valueOf(serialNumberBase++);
    }

    /**
     * Simple method to convert an X509CertificateHolder to an X509Certificate
     * using the java.security.cert.CertificateFactory class.
     */
    public static X509Certificate convertX509CertificateHolder(
                                             X509CertificateHolder certHolder)
            throws GeneralSecurityException, IOException
    {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");

        return (X509Certificate)cFact.generateCertificate(
                                           new ByteArrayInputStream(
                                                   certHolder.getEncoded()));
    }

    /**
     * Convert an X500Name to use the IETF style.
     */
    public static X500Name toIETFName(X500Name name)
    {
        return X500Name.getInstance(RFC4519Style.INSTANCE, name);
    }

    public static X509KeyCertPair createTrustCert()
            throws GeneralSecurityException, OperatorCreationException
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair trustKp = kpGen.generateKeyPair();

        X509CertificateHolder trustCert =
                                  createTrustAnchor(trustKp, "SHA256withECDSA");
        return new X509KeyCertPair(trustKp, trustCert);
    }

    /**
     * Build a sample self-signed V1 certificate to use as a trust anchor, or
     * root certificate.
     *
     * @param keyPair the key pair to use for signing and providing the
     *                public key.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @return an X509CertificateHolder containing the V1 certificate.
     */
    public static X509CertificateHolder createTrustAnchor(
            KeyPair keyPair, String sigAlg)
            throws OperatorCreationException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo Root Certificate");

        X500Name name = x500NameBld.build();

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                                                    name,
                                                    calculateSerialNumber(),
                                                    calculateDate(0),
                                                    calculateDate(24 * 31),
                                                    name,
                                                    keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                .setProvider("BC").build(keyPair.getPrivate());

        return certBldr.build(signer);
    }

    public static X509KeyCertPair createInterCert(X509KeyCertPair trustPair)
            throws GeneralSecurityException, OperatorCreationException, CertIOException
    {
        PrivateKey trustAnchorKey = trustPair.getKeyPair().getPrivate();
        X509CertificateHolder trustCert = trustPair.getCert();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair caKp = kpGen.generateKeyPair();

        X509CertificateHolder caCert =
                createIntermediateCertificate(trustCert,
                        trustAnchorKey,
                        "SHA256withECDSA", caKp.getPublic(), 0);
        return new X509KeyCertPair(caKp, caCert);
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA
     * certificate.
     *
     * @param signerCert certificate carrying the public key that will later
     *                   be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     *                  certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @param followingCACerts
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createIntermediateCertificate(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, int followingCACerts)
            throws CertIOException, GeneralSecurityException,
                   OperatorCreationException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo Intermediate Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(
                                              KeyUsage.digitalSignature
                                            | KeyUsage.keyCertSign
                                            | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }

    public static X509KeyCertPair createEECert(X509KeyCertPair caPair)
            throws GeneralSecurityException, OperatorCreationException, CertIOException
    {
        PrivateKey caPrivKey = caPair.getKeyPair().getPrivate();
        X509CertificateHolder caCert = caPair.getCert();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair eeKp = kpGen.generateKeyPair();

        X509CertificateHolder eeCert =
                createEndEntity(caCert, caPrivKey, "SHA256withECDSA", eeKp.getPublic());

        return new X509KeyCertPair(eeKp, eeCert);
    }

    /**
     * Create a general end-entity certificate for use in verifying digital
     * signatures.
     * 
     * @param signerCert certificate carrying the public key that will later
     *                   be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     *                  certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createEndEntity(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey)
            throws CertIOException, GeneralSecurityException,
                   OperatorCreationException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo End-Entity Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder   certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                       .setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }

    public static X509KeyCertPair createEESpecCert(X509KeyCertPair caPair)
            throws GeneralSecurityException, OperatorCreationException, CertIOException
    {
        PrivateKey caPrivKey = caPair.getKeyPair().getPrivate();
        X509CertificateHolder caCert = caPair.getCert();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair specEEKp = kpGen.generateKeyPair();

        X509CertificateHolder specEECert =
                createSpecialPurposeEndEntity(caCert, caPrivKey,
                                               "SHA256withECDSA",
                                               specEEKp.getPublic(),
                                               KeyPurposeId.id_kp_timeStamping);
        return new X509KeyCertPair(specEEKp, specEECert);
    }

    /**
     * Create a special purpose end entity cert which is associated with a
     * particular key purpose.
     * 
     * @param signerCert certificate carrying the public key that will later
     *                   be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     *                  certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @param keyPurpose the specific KeyPurposeId to associate with this
     *                   certificate's public key.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createSpecialPurposeEndEntity(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, KeyPurposeId keyPurpose)
            throws OperatorCreationException, CertIOException,
                   GeneralSecurityException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo End-Entity Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder   certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.extendedKeyUsage,
                              true, new ExtendedKeyUsage(keyPurpose));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                       .setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }
    /**
     * Extract the DER encoded value octets of an extension from a JCA
     * X509Certificate.
     *
     * @param cert the certificate of interest.
     * @param extensionOID the OID associated with the extension of interest.
     * @return the DER encoding inside the extension, null if extension missing.
     */
    public static byte[] extractExtensionValue(
            X509Certificate cert,
            ASN1ObjectIdentifier extensionOID)
    {
        byte[] octString = cert.getExtensionValue(extensionOID.getId());

        if (octString == null)
        {
            return null;
        }

        return ASN1OctetString.getInstance(octString).getOctets();
    }

    public static X509AttributeCertificateHolder createAttrCertSample(PrivateKey issuerSigningKey,  X509CertificateHolder issuerCert, X509CertificateHolder holderCert)
            throws OperatorCreationException
    {
        X509AttributeCertificateHolder attrCert =
                createAttributeCertificate(issuerCert,
                        issuerSigningKey,
                        "SHA256withECDSA", holderCert, "id://DAU123456789");
        return attrCert;
    }

    public static X509AttributeCertificateHolder createAttributeCertificate(
            X509CertificateHolder issuerCert, PrivateKey issuerKey, String sigAlg,
            X509CertificateHolder holderCert, String holderRoleUri)
            throws OperatorCreationException
    {
        X509v2AttributeCertificateBuilder acBldr =
                new X509v2AttributeCertificateBuilder(
                      new AttributeCertificateHolder(holderCert),
                      new AttributeCertificateIssuer(issuerCert.getSubject()),
                      calculateSerialNumber(),
                      calculateDate(0),
                      calculateDate(24 * 7));

        GeneralName roleName = new GeneralName(
                         GeneralName.uniformResourceIdentifier, holderRoleUri);

        acBldr.addAttribute(
                 X509AttributeIdentifiers.id_at_role, new RoleSyntax(roleName));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(issuerKey);
        
        return acBldr.build(signer);
    }
}
