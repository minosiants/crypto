package chapter8;

import org.bouncycastle.cert.X509CertificateHolder;

import java.security.KeyPair;

public class X509KeyCertPair
{
    private final KeyPair keyPair;
    private final X509CertificateHolder cert;

    public X509KeyCertPair(KeyPair keyPair, X509CertificateHolder cert)
    {
        this.keyPair = keyPair;
        this.cert = cert;
    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }

    public X509CertificateHolder getCert()
    {
        return cert;
    }
}
