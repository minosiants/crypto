package chapter10;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

import static chapter6.EcDsaUtils.generateECKeyPair;
import static chapter8.JcaX509Certificate.createTrustAnchor;

public class KeyStoreUtils
{
    /**
     * Create a private key with an associated self-signed certificate
     * returning them wrapped in an X500PrivateCredential
     *
     * Note: We use generateECKeyPair() from chapter6.EcDsaUtils and
     * createTrustAnchor() from chapter8.JcaX509Certificate.
     *
     * @return an X500PrivateCredential containing the key and its certificate.
     */
    public static PrivateCredential createSelfSignedCredentials()
        throws GeneralSecurityException, OperatorCreationException
    {
        JcaX509CertificateConverter certConverter =
                           new JcaX509CertificateConverter().setProvider("BC");

        KeyPair selfSignedKp = generateECKeyPair();

        X509CertificateHolder selfSignedHldr =
                           createTrustAnchor(selfSignedKp, "SHA256withECDSA");

        X509Certificate selfSignedCert = certConverter.getCertificate(selfSignedHldr);

        return new PrivateCredential(selfSignedCert, selfSignedKp.getPrivate());
    }
}
