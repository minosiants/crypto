package chapter15;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

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
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;

import static chapter15.XMSSUtils.generateXMSSKeyPair;
import static chapter15.XMSSUtils.getXMSSSignatureIndex;
import static chapter8.JcaX509Certificate.calculateDate;

/**
 * Example of building an XMSS based certificate - self-signed in this case.
 */
public class XMSSCertExample
{
    /**
     * Create an X.509 certificate signed by an XMSS key, using
     * the signature index as the serial number.
     *
     * @param privKey the XMSS private key to use.
     * @param issuer the issuer name for the certificate.
     * @param pubKey the public key to be held in the certificate.
     * @param subject the name to associate with the public key.
     * @return an X.509 certificate holder.
     */
    public static X509CertificateHolder createXMSSCertificate(
        XMSSPrivateKey privKey, X500Name issuer,
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

        ContentSigner signer = new JcaContentSignerBuilder("XMSS")
                                .setProvider("BCPQC").build(privKey);

        return certBldr.build(signer);
    }

    public static void main(String[] args)
        throws Exception
    {
        X500Name name = new X500Name("CN=XMSS Demo Root Certificate");

        KeyPair kp = generateXMSSKeyPair();
        XMSSPrivateKey privKey = (XMSSPrivateKey)kp.getPrivate();

        // we throw away our signature with index 0 - RFC 5280 requires
        // certificate serial numbers > 0.
        privKey.extractKeyShard(1);
        
        X509CertificateHolder certHldr = createXMSSCertificate(
                                            privKey, name, kp.getPublic(), name);

        System.out.println("key index: " + privKey.getIndex());
        System.out.println("serial no: " + certHldr.getSerialNumber());
        System.out.println("sig index: "
                       + getXMSSSignatureIndex(certHldr.getSignature()));
        System.out.println("verifies : " + certHldr.isSignatureValid(
            new JcaContentVerifierProviderBuilder()
                .setProvider("BCPQC").build(kp.getPublic())));
    }
}
