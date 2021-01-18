package chapter10;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Carrier class for a private key and its corresponding public key certificate.
 * <p>
 * The regular Java API also has javax.security.auth.x500.X500PrivateCredential,
 * this class is a basic replacement for that. There is also a slightly more
 * general class in the BC PKIX API - org.bouncycastle.pkix.PKIXIdentity.
 * </p>
 */
public class PrivateCredential
{
    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    /**
     * Base constructor.
     *
     * @param certificate the public key certificate matching privateKey.
     * @param privateKey the private key matching the certificate parameter.
     */
    public PrivateCredential(X509Certificate certificate, PrivateKey privateKey)
    {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }
}
