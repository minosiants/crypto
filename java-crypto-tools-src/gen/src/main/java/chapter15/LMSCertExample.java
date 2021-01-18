package chapter15;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import static chapter15.LMSUtils.generateLMSKeyPair;
import static chapter15.LMSUtils.getLMSSignatureIndex;
import static chapter15.XMSSUtils.generateXMSSKeyPair;
import static chapter15.XMSSUtils.getXMSSSignatureIndex;
import static chapter8.JcaX509Certificate.calculateDate;

/**
 * Example of building an LMS based certificate - self-signed in this case.
 */
public class LMSCertExample
{
    /**
     * Create an X.509 certificate signed by an LMS key, using
     * the signature index as the serial number.
     *
     * @param privKey the LMS private key to use.
     * @param issuer the issuer name for the certificate.
     * @param pubKey the public key to be held in the certificate.
     * @param subject the name to associate with the public key.
     * @return an X.509 certificate holder.
     */
    public static X509CertificateHolder createLMSCertificate(
        LMSPrivateKey privKey, X500Name issuer,
        PublicKey pubKey, X500Name subject)
        throws OperatorCreationException
    {
        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                                        issuer,
                                        BigInteger.valueOf(privKey.getIndex()),
                                        calculateDate(0),
                                        calculateDate(24 * 31),
                                        subject,
                                        pubKey);

        ContentSigner signer = new JcaContentSignerBuilder("LMS")
                                .setProvider("BCPQC").build(privKey);

        return certBldr.build(signer);
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastlePQCProvider());
        
        X500Name name = new X500Name("CN=LMS Demo Root Certificate");

        KeyPair kp = generateLMSKeyPair();
        LMSPrivateKey privKey = (LMSPrivateKey)kp.getPrivate();

        // we throw away our signature with index 0 - RFC 5280 requires
        // certificate serial numbers > 0.
        privKey.extractKeyShard(1);
        
        X509CertificateHolder certHldr = createLMSCertificate(
                                            privKey, name, kp.getPublic(), name);

        System.out.println("key index: " + privKey.getIndex());
        System.out.println("serial no: " + certHldr.getSerialNumber());
        System.out.println("sig index: "
                       + getLMSSignatureIndex(certHldr.getSignature()));
        System.out.println("verifies : " + certHldr.isSignatureValid(
            new JcaContentVerifierProviderBuilder()
                .setProvider("BCPQC").build(kp.getPublic())));
    }
}
