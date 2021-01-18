package chapter12;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Example methods showing generation and verification of a PKCS#10 requests.
 */
public class JcaPKCS10
{
    /**
     * Create a PKCS#10 request including an extension request detailing the
     * email address the CA should include in the subjectAltName extension.
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg the signature algorithm to sign the PKCS#10
     *                           request with.
     * @return an object carrying the PKCS#10 request.
     * @throws OperatorCreationException in case the private key is
     * inappropriate for signature algorithm selected.
     * @throws IOException on an ASN.1 encoding error.
     */
    public static PKCS10CertificationRequest createPKCS10WithExtensions(
            KeyPair keyPair, String sigAlg)
            throws OperatorCreationException, IOException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder
                = new JcaPKCS10CertificationRequestBuilder(
                                            subject, keyPair.getPublic());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(
                        new GeneralName(
                                GeneralName.rfc822Name,
                                "feedback-crypto@bouncycastle.org")));

        Extensions extensions = extGen.generate();

        requestBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                .setProvider("BC").build(keyPair.getPrivate());

        return requestBuilder.build(signer);
    }
    /**
     * Create a basic PKCS#10 request.
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg the signature algorithm to sign the PKCS#10 request with.
     * @return an object carrying the PKCS#10 request.
     * @throws OperatorCreationException in case the private key is
     * inappropriate for signature algorithm selected.
     */
    public static PKCS10CertificationRequest createPKCS10(
            KeyPair keyPair, String sigAlg)
            throws OperatorCreationException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder
                = new JcaPKCS10CertificationRequestBuilder(
                                            subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                                .setProvider("BC").build(keyPair.getPrivate());

        return requestBuilder.build(signer);
    }
    /**
     * Simple method to check the signature on a PKCS#10 certification test with
     * a public key.
     *
     * @param request the encoding of the PKCS#10 request of interest.
     * @return true if the public key verifies the signature, false otherwise.
     * @throws OperatorCreationException in case the public key is unsuitable
     * @throws PKCSException if the PKCS#10 request cannot be processed.
     */
    public static boolean isValidPKCS10Request(
            byte[] request)
        throws OperatorCreationException, PKCSException,
               GeneralSecurityException, IOException
    {
        JcaPKCS10CertificationRequest jcaRequest =
                    new JcaPKCS10CertificationRequest(request).setProvider("BC");
        PublicKey key = jcaRequest.getPublicKey();

        ContentVerifierProvider verifierProvider =
                                       new JcaContentVerifierProviderBuilder()
                                           .setProvider("BC").build(key);

        return jcaRequest.isSignatureValid(verifierProvider);
    }
}
